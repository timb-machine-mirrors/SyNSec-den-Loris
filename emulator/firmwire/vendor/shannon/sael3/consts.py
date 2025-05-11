from enum import Enum

MsgId = int
Uid = str


class SAEL3MsgType(Enum):
    SAEMM_EXT = 0
    SAEMM_INT = 1
    SAEMM_RADIO = 3
    SAERC_EXT = 4
    SAERC_INT = 5
    SAERC_RADIO = 6
    SAEQM_EXT = 7
    SAEQM_INT = 8
    SAEQM_RADIO = 9
    UNKNOWN = 0xa


class SAEL3Constants:
    SAEMM_StateProcName = "emm_proc"
    SAEMM_StateASName = "emm_as"

    SAEMM_NumStateProc = 18
    SAEMM_NumStateAS = 7

    # msg_id + msg_name + handlers[18][7] + default_handler + prepost
    SAEMM_ExtMsgDispatchStructSize = 4 + 4 + SAEMM_NumStateProc * SAEMM_NumStateAS * 4 + 4 + 4
    SAEMM_ExtMsgHandlerStructSize = 0x10
    SAEMM_IEDispatchStructSize = 0x10
