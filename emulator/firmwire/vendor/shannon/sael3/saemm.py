import struct

from abc import ABC, abstractmethod
from typing import Tuple

from .consts import SAEL3Constants


class SAEMM(ABC):
    @property
    @abstractmethod
    def shannon(self):
        pass

    @abstractmethod
    def get_prepost(self, prepost):
        raise NotImplementedError("Must override get_prepost")

    def saemm_get_state_id_security(self) -> int:
        state_ptr = 0x425294ec

        (state_id,) = struct.unpack("B", self.shannon.physical_memory_read(state_ptr, 1))
        return state_id

    def saemm_get_state_name_security(self, state_id: int) -> str:
        pass

    def saemm_get_state_id_as(self) -> int:
        state_ptr = 0x425299e4

        (state_id,) = struct.unpack("B", self.shannon.physical_memory_read(state_ptr, 1))
        return state_id

    def saemm_get_state_name_as(self, state_id: int) -> str:
        state_names_ptr = 0x425193d8
        undef_name_ptr = 0x40fdd3c8
        max_id = SAEL3Constants.SAEMM_NumStateAS

        (name_ptr,) = self.shannon.physical_memory_read(state_names_ptr + state_id * 4, 4)

        if state_id < 0 or max_id <= state_id or name_ptr == 0:
            return self.shannon.read_cstring_panda(undef_name_ptr)
        else:
            return self.shannon.read_cstring_panda(name_ptr)

    def saemm_get_state_id_proc(self) -> int:
        state_ptr = 0x425299e1

        (state_id,) = struct.unpack("B", self.shannon.physical_memory_read(state_ptr, 1))
        return state_id

    def saemm_get_state_proc_struct(self, head: int, state_id: int) -> dict:
        """saemm_get_state_proc_struct
        struct SAEMM_StateProc {
            char *state_name;
            byte state_id_main;
            byte state_id_service;
            ushort unk;
        }"""
        struct_size = 8

        ptr = head + state_id * struct_size

        state_struct = self.shannon.physical_memory_read(
            ptr, struct_size
        )

        (state_name_ptr, state_id_main, state_id_service, _) = struct.unpack(
            "<IBBH", state_struct
        )
        if state_name_ptr == 0:
            return {}
        state_name = self.shannon.read_cstring_panda(state_name_ptr)

        return {
            "state_name": state_name,
            "state_id_main": state_id_main,
            "state_id_service": state_id_service,
        }

    def saemm_get_state_name_proc(self, state_id: int) -> str:
        state_structs_ptr = 0x4252f524
        default_name_ptr = 0x40e40028
        max_id = SAEL3Constants.SAEMM_NumStateProc

        if state_id < 1 or max_id <= state_id:
            return self.shannon.read_cstring_panda(default_name_ptr)

        state_struct = self.saemm_get_state_proc_struct(state_structs_ptr, state_id)
        if state_struct:
            return state_struct["state_name"]
        else:
            return self.shannon.read_cstring_panda(default_name_ptr)

    def saemm_get_msg_dispatch_table(self, head, num):
        items = {}
        for i in range(num):
            msg_id, dispatch_struct = self.saemm_get_msg_dispatch_struct(head, i)
            if dispatch_struct:
                items[msg_id] = dispatch_struct

        return items

    def saemm_get_msg_handler(self, ptr: int) -> dict:
        """saemm_get_msg_handler
        struct SAEL3_MsgHandler {
            byte emm_proc;
            byte emm_as;
            undefined field2_0x2;
            undefined field3_0x3;
            SAEL3_MsgHandlerFunc *func;
            byte default_emm_proc;
            undefined field6_0x9;
            undefined field7_0xa;
            undefined field8_0xb;
            char *func_name;
        };
        """
        struct_size = SAEL3Constants.SAEMM_ExtMsgHandlerStructSize
        if ptr == 0:
            return {}

        handler_struct = self.shannon.physical_memory_read(
            ptr, struct_size
        )

        (state_proc, state_as, _, func_ptr, default_proc, _, _, func_name_ptr) = struct.unpack(
            "<BBHIBBHI", handler_struct
        )
        if func_name_ptr == 0 or func_ptr == 0:
            return {}

        func_name = self.shannon.read_cstring_panda(func_name_ptr)
        return {
            "addr": ptr,
            "func": func_ptr,
            "func_name": func_name,
            SAEL3Constants.SAEMM_StateProcName: state_proc,
            SAEL3Constants.SAEMM_StateASName: state_as,
            "default_emm_proc": default_proc,
        }

    def saemm_get_msg_dispatch_struct(self, head: int, msg_idx: int) -> Tuple[int, dict]:
        """saemm_get_msg_dispatch_struct
        struct SAEMM_MsgDispatchTableStruct {
            ushort msg_id;
            ushort unused;
            char *msg_name;
            SAEL3_MsgHandler *[18][7] handlers;
            SAEL3_MsgHandler *default_handler;
            SAEL3_PrePostHandler *prepost;
        }"""
        struct_size = SAEL3Constants.SAEMM_ExtMsgDispatchStructSize

        num_as = SAEL3Constants.SAEMM_NumStateAS
        num_proc = SAEL3Constants.SAEMM_NumStateProc

        msg_id_offset = 0
        msg_name_ptr_offset = 4
        handlers_offset = 8
        default_handler_offset = 0x200
        prepost_offset = 0x204

        ptr = head + msg_idx * struct_size

        handler_struct = self.shannon.physical_memory_read(
            ptr, struct_size
        )

        (msg_id, msg_name_ptr, default_handler_ptr, prepost_ptr) = struct.unpack(
            "<HIII",
            handler_struct[msg_id_offset: msg_id_offset + 2] +
            handler_struct[msg_name_ptr_offset: msg_name_ptr_offset + 4] +
            handler_struct[default_handler_offset: default_handler_offset + 4] +
            handler_struct[prepost_offset: prepost_offset + 4]
        )
        handlers_ptr = struct.unpack(f"<{num_as * num_proc}I",
                                     handler_struct[handlers_offset: handlers_offset + 4 * num_as * num_proc])

        if msg_name_ptr == 0:
            return msg_id, {}
        msg_name = self.shannon.read_cstring_panda(msg_name_ptr)

        handlers = []
        for i in range(num_proc):
            for j in range(num_as):
                handler_ptr = handlers_ptr[i * num_as + j]
                handler = self.saemm_get_msg_handler(handler_ptr)
                if not handler:
                    continue
                handlers.append(handler)

        default_handler = self.saemm_get_msg_handler(default_handler_ptr)
        prepost_handler = self.get_prepost(prepost_ptr)

        return msg_id, {
            "msg_id": msg_id,
            "name": msg_name,
            "handlers": handlers,
            "default_handler": default_handler,
            "prepost_handler": prepost_handler,
        }

    def saemm_get_ie_dispatch_table(self, head: int, num: int):
        items = {}
        for i in range(num):
            virt_iei, dispatch_struct = self.saemm_get_ie_dispatch_table_struct(head, i)
            if dispatch_struct:
                items[virt_iei] = dispatch_struct

        return items

    def saemm_get_ie_dispatch_table_struct(self, head: int, ie_idx: int) -> Tuple[int, dict]:
        """saemm_get_ie_dispatch_struct
        struct SAEL3_IeDispatchTableStruct {
            ushort virt_iei;
            ushort unused;
            SAEL3_IeToRawFunc *to_raw;
            SAEL3_IeFromRawFunc *from_raw;
            char *msg_name;
        }"""
        struct_size = SAEL3Constants.SAEMM_IEDispatchStructSize

        ptr = head + ie_idx * struct_size

        dispatch_struct = self.shannon.physical_memory_read(
            ptr, struct_size
        )

        (iei, _, func_1, func_2, ie_name_ptr) = struct.unpack(
            "<HHIII", dispatch_struct
        )

        if ie_name_ptr == 0:
            return iei, {}
        ie_name = self.shannon.read_cstring_panda(ie_name_ptr)

        return iei, {
            "addr": head,
            "virt_iei": iei,
            "to_raw": func_1,
            "from_raw": func_2,
            "ie_name": ie_name,
        }
