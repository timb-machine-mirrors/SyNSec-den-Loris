import hashlib
import logging
import struct

from typing import Dict
from graphviz import Digraph
from queue import PriorityQueue

from .consts import *
from .qitem import SAEL3QItem
from .saemm import SAEMM
from firmwire.vendor.shannon.machine import ShannonMachine
from firmwire.vendor.shannon.pal_structs import PALMsg

log = logging.getLogger(__name__)


class SAEL3StateMachineException(Exception):
    def __init__(self, message):
        super().__init__(message)


class SAEL3MsgDispatchStruct:
    def __init__(self, msg_id: MsgId):
        self._msg_id = msg_id


class StateTransition:
    def __init__(self, dst_state_id: int, qitem: SAEL3QItem) -> None:
        self._dst_state_id = dst_state_id
        self._qitem = qitem

    @property
    def dst_state_id(self):
        return self._dst_state_id

    @property
    def qitem(self):
        return self._qitem

    def __str__(self) -> str:
        return f"Transition< dst_state={self._dst_state_id}, msg={self._qitem} >"


class SAEL3State:
    def __init__(self, name, state_id) -> None:
        self.name = name
        self.id = state_id
        self.transitions: Dict[str, StateTransition] = {}

    def add_transition(self, dst_state_id: int, qitem: SAEL3QItem):
        log.info(f"\t\tSAEL3State.add_transition(dst_state_id={dst_state_id}, msg={qitem})")

        self.transitions[qitem.uid] = StateTransition(dst_state_id, qitem)
        # if transition.dst_state_id in self.transitions.keys():
        #     transitions = self.transitions[transition.dst_state_id]
        #     transitions.append(transition)
        # else:
        #     self.transitions[transition.dst_state_id] = [transition]


class SAEL3StateMachine:
    def __init__(self) -> None:
        self.start_state_id = None
        self.curr_state_id = None
        self.states: Dict[Uid, SAEL3State] = {}

    def update_curr_state(self, state_id) -> None:
        log.info(f"\tSAEL3StateMachine.update_curr_state(state_id={state_id})")
        self.curr_state_id = state_id

    def update_state(self, state_id: int, qitem: SAEL3QItem):
        log.info(f"\tSAEL3StateMachine.update_state(state_id={state_id}, msg={qitem})")

        if qitem is None:
            if self.start_state_id is not None:
                raise SAEL3StateMachineException(
                    f"Get another start state {state_id} while it is {self.start_state_id}")
            self.start_state_id = state_id
            return

        if self.curr_state_id not in self.states.keys():
            self.states[self.curr_state_id] = SAEL3State(f"{self.curr_state_id}", self.curr_state_id)
        self.states[self.curr_state_id].add_transition(state_id, qitem)

    def is_tried(self, uid: Uid) -> bool:
        return uid in self.states.keys()


class SAEL3(SAEMM):
    messages: Dict[SAEL3MsgType, Dict[MsgId, SAEL3MsgDispatchStruct]] = {}

    def __init__(self, shannon: ShannonMachine) -> None:
        super().__init__()

        self._shannon = shannon
        self._qitem: SAEL3QItem = None
        self.state_proc = SAEL3StateMachine()
        self.state_as = SAEL3StateMachine()
        self._fuzzer_curr_msg = set()
        self._fuzzer_msg_corpus = PriorityQueue()

    @property
    def shannon(self):
        return self._shannon

    @property
    def fuzzer_msg_corpus(self):
        return self._fuzzer_msg_corpus

    @property
    def fuzzer_curr_msg(self):
        return self._fuzzer_curr_msg

    @staticmethod
    def detect_msg_type(msg_id: MsgId) -> SAEL3MsgType:
        for msg_type, messages in SAEL3.messages.items():
            if msg_id in messages.keys():
                return msg_type
        return SAEL3MsgType.UNKNOWN

    def calc_msg_uid(self, qitem: SAEL3QItem) -> Uid:
        if len(qitem.data) < struct.calcsize(qitem.pld_pattern):
            raise ValueError(f"SAEL3QItem requires {len(qitem.data)} bytes in payload")

        if qitem.msg_type == SAEL3MsgType.SAEMM_EXT:
            (unk, pl_size, _, asn_pl_ptr) = struct.unpack(qitem.pld_pattern, qitem.data)
            h = hashlib.sha3_256()
            h.update(struct.pack(qitem.uid_pattern, qitem.msg_id, unk, pl_size, 0))
            h.update(self._shannon.read_physycal_memory(asn_pl_ptr, pl_size))
            unique_id = h.hexdigest()
        else:
            raise ValueError("")

        return unique_id

    def update_curr_state(self, state_name, state_id) -> None:
        log.info(f"SAEL3.update_curr_state(state_name={state_name}, state_id={state_id})")
        if state_name == SAEL3Constants.SAEMM_StateProcName:
            self.state_proc.update_curr_state(state_id)

    def update_state(self, state_name: str, state_id: int) -> None:
        log.info(f"SAEL3.update_state(state_name={state_name}, state_id={state_id})")
        if state_name == SAEL3Constants.SAEMM_StateProcName:
            self.state_proc.update_state(state_id, self._qitem)

    def is_msg_tried(self, uid: Uid) -> bool:
        """is_tried
        Returns true if the message with unique ID, uid, has been tried in the current state of SAEL3
        """
        return self.state_proc.is_tried(uid)

    def any_state_changed(self):
        pass

    def msg_received(self, qitem: PALMsg) -> None:
        log.info(f"SAEL3.msg_received(msg={qitem})")

        sael3_qitem = SAEL3QItem(qitem)
        sael3_qitem.msg_type = self.detect_msg_type(sael3_qitem.msg_id)
        sael3_qitem.uid = self.calc_msg_uid(sael3_qitem)
        if sael3_qitem.uid not in self.fuzzer_curr_msg:
            return
        self._qitem = sael3_qitem

        self.fuzzer_curr_msg.remove(self._qitem.uid)

    def waiting_for_msg(self):
        log.info(f"SAEL3.waiting_for_msg()")
        self._qitem = None

    def render_state_machine(self):
        dot = Digraph()
        for state in self.state_proc.states.values():
            dot.node(state.name, state.name)
            for t in state.transitions.values():
                # TODO: get dst state by id
                dot.edge(state.name, f"{t.dst_state_id}", label=str(t.qitem))

        dot.render(filename='SAEL3-EmmProc')

    def get_msg_forward_table(self, head: int, num: int):
        items = {}
        for i in range(num):
            forward_struct = self.get_msg_forward_struct(head, i)
            if forward_struct:
                forward_struct['idx'] = hex(i)
                items[i] = forward_struct

        return items

    def get_msg_forward_struct(self, head: int, idx: int) -> dict:
        """sael3_get_msg_forward_struct
        struct SAEL3_MsgForwardTableStruct{
            ushort op;
            byte sync_type;
            byte unused1;
            ushort pl_size;
            PALQueueID src_qid;
            PALQueueID dst_qid;
            ushort unused2;
            void (*)(ushort) func;
            char *func_name;
            char *msg_name;
            char *msg_type;
            ushort rsp_msg_id;
            ushort unused3;
            uint field_20;
            void (*)(void) rsp_func;
            char *rsp_msg_name;
            char *rsp_func_name;
        }"""
        struct_size = 0x30

        qlist = self._shannon.get_queues()
        ptr = head + idx * struct_size

        forward_struct = self._shannon.physical_memory_read(
            ptr, struct_size
        )

        (op, sync_type, _, pl_size, src_qid, dst_qid, _, func_ptr, func_name_ptr, msg_name_ptr, msg_type_ptr,
         rsp_msg_id, _, field_20, rsp_func_ptr, rsp_msg_name_ptr, rsp_func_name_ptr) = struct.unpack(
            "<HBBHHHHIIIIHHIIII", forward_struct
        )
        if msg_name_ptr == 0:
            return {}
        msg_name = self._shannon.read_cstring_panda(msg_name_ptr)

        dst_qname = ""
        if 0 <= dst_qid < len(qlist):
            dst_qname = qlist[dst_qid].name
        src_qname = ""
        if 0 <= src_qid < len(qlist):
            src_qname = qlist[src_qid].name
        func_name = ""
        if func_name_ptr != 0:
            func_name = self._shannon.read_cstring_panda(func_name_ptr)
        msg_type = ""
        if msg_type_ptr != 0:
            msg_type = self._shannon.read_cstring_panda(msg_type_ptr)

        rsp_msg_name = ""
        if rsp_msg_name_ptr != 0:
            rsp_msg_name = self._shannon.read_cstring_panda(rsp_msg_name_ptr)
        rsp_func_name = ""
        if rsp_func_name_ptr:
            rsp_func_name = self._shannon.read_cstring_panda(rsp_func_name_ptr)

        return {
            "op": op,
            "op_hex": hex(op),
            "sync_type": sync_type,
            "pl_size": pl_size,
            "src_qid": src_qid,
            "src_qname": src_qname,
            "dst_qid": dst_qid,
            "dst_qname": dst_qname,
            "func": func_ptr,
            "func_name": func_name,
            "msg_name": msg_name,
            "msg_type": msg_type,
            "rsp_msg_id": rsp_msg_id,
            "field_20": field_20,
            "rsp_func": rsp_func_ptr,
            "rsp_func_hex": hex(rsp_func_ptr),
            "rsp_msg_name": rsp_msg_name,
            "rsp_func_name": rsp_func_name,
        }

    def get_prepost(self, ptr: int) -> dict:
        """sael3_get_prepost
        struct SAEL3_PrePostHandler {
            void (*)(byte *) pre_handler;
            void (*)(byte *) post_handler;
        }
        """
        struct_size = 8

        if ptr == 0:
            return {}

        prepost_struct = self._shannon.physical_memory_read(ptr, struct_size)
        (pre_func_ptr, post_func_ptr) = struct.unpack("<II", prepost_struct)

        return {
            "addr": ptr,
            "p_pre_handler": pre_func_ptr,
            "p_post_handler": post_func_ptr,
        }
