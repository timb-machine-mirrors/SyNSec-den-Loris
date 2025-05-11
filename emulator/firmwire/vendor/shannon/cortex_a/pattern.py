import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS = {
    "boot_key_check": {
        "pattern": [
            "08 80 19 f0 a5 fe e2 a0 25 f2 f5 f3 06 f0 26 fd 05 f0 bc f8 3a ac 80 21 20 46 b8 f3 dd db 1a a9 20 46 10 22 56 f2 f4 d3",
        ],
        "offset_end": 0x0,
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": "f0 b5 81 b0 04 46 00 f0 da e8 05 46 00 f0 d6 e8 41 f2 40 66 c4 f2 10 56 71 79 88 42",
    },
    "pal_MemAlloc": {
        "pattern": "2d e9 f0 4f  ?? ?? ?? ?? ?? ?? 80 46 0c 46 9a 46",
    },
    "pal_MemFree_Wrapper": {
        "pattern": "2d e9 f0 4f 89 b0 ???????? cd e9 04 21 07 46 ???????? da f8 00 00",
    },
    "pal_MsgSendTo": {
        "pattern": [
            "70 b5 ?+ 04 46 15 46 0e 46 ?? ?? 01 df ?* 88 60 08 46 ?+ ?? 48 ???? ???? 20 46 98 47",  # G973F
            "???????? b0f5fa7f 0446 ??46",  # S337AP
            "2d e9 f0 47 82 b0 06 46 91 46 8a 46 ?+ 01 df ?+ 81 60 ?+ 14 24 ???? ?+ 03 68",  # G991B
        ]
    },
    "disableIRQinterrupts": {
        "pattern": "00 00 0f e1 80 00 00 e2 80 00 0c f1 1e ff 2f e1",
        "align": 4,
    },
    "enableIRQinterrupts": {
        "pattern": "80 00 10 e3 ?? 00 00 1a 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "disableIRQinterrupts_trap": {
        "pattern": "00 00 0f e1 80 00 10 e2 ?+ 80 00 0c f1",
        "align": 4,
    },
    "enableIRQinterrupts_trap": {
        "pattern": "80 00 10 e3 ?? 00 00 1a ?+ 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "pal_Sleep": {
        "pattern": "01 21 e9 f6 1d 9d",
        # 30 b5 00 25 83 b0 04 46 2a 46 29 46 01 a8 d9 f6 2a e9 01 98 78 b1 29 46 d9 f6 90 e8 01 98 01 22 00 23 11 46 00 94 d9 f6 36 e9 01 98 d8 f6 5e ee 01 98 d9 f6 28 e9 5c f7 09 d8 00 28 02 d0 02 a8 ff f7 42 fe 03 b0 30 bd
        # 30 b5 04 46 85 b0 df 4b 40 f2 02 30 00 22 00 90 11 46 01 a8 0e f1 54 ee dd f8 04 c0 bc f1 00 0f 1c d0 00 25 01 21 03 ab 2a 46 0c f1 38 00 00 95 65 f4 1a f1 01 98 29 46 8b f1 a8 ed 01 98 01 22 00 23 11 46 00 94 5b f1 58 ed 01 98 8b f1 2e ec cd 49 40 f2 13 32 01 98 8b f1 a0 ed f0 f4 a1 f0 00 28 02 d0 02 a8 ff f7 1a fe 05 b0 30 bd
    },
    "log_printf": {
        "pattern": "83b0 2de9f0?? ???? ???????? 0df14c0c 0024",
        "required": True,
    },
    # log_printf_debug
    "log_printf2": {
        "pattern": [
            "0fb4 2de9f04f ???? ???? ??b0??98 4068",
            "b0 b5 86 b0 45 f2 ec 64 c4 f2 b5 24 20 68 05 90 00 20 04 90 04 a8 e8 f0 1e f8 38 b1 01 20",
        ],
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10 b5 ???? ???? ???????? 04 46 ???????? 04 42 ???? ???????? 20 b2",  # G991B
            "10b5 ???? ???????? 04 b2",  # thumb G973F, no NULL check
            "10b5 0068 0028 ???? ???????? 04 b2",  # thumb S337AP, NULL check
        ],
    },
    # OS_Delete_Event_Group is the function (based off string name). It is in the baseband (2017+) otherwise search for string
    # "LTE_RRC_EVENT_GRP_NAME" to find the creation function and explore from there.
    "SYM_EVENT_GROUP_LIST": {
        "lookup": handlers.find_event_group_list,
    },
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "SYM_SCHEDULABLE_TASK_LIST": {"lookup": handlers.find_schedulable_task_table},
    "SYM_CUR_TASK_ID": {"lookup": handlers.find_current_task_ptr},
    "SYM_CUR_TASK_PTR": {"lookup": handlers.find_current_task_ptr_a},
    "SYM_FN_EXCEPTION_SWITCH": {"lookup": handlers.find_exception_switch},
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "QUIRK_SXXXAP_DVFS_HACK": {
        "pattern": [
            "??f8???? 00f01f01 ??48 d0 f8 ????  c0 f3 ????  ????????  ????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",
            "????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",  # S335AP alternate
        ],
        "offset_end": 0x0,
        "soc_match": ["S335AP", "S355AP", "S360AP"],
        # Thumb alignment
        "align": 2,
        "required": True,
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": handlers.find_lterrc_int_mob_cmd_ho_from_irat_msgid
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "??21??68 4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ???????? ???????? ???????? ??b0bde8 f0 ??",
        ],
        "post_lookup": handlers.get_dsp_sync0,
        "required": False,
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ???????? ???????? ???????? ??b0bde8 f0 ??",
        ],
        "offset": 2,
        "offset_end": 3,
        "post_lookup": handlers.get_dsp_sync1,
        "required": False,
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "70 b5 82 b0 45 f2 ec 66 14 46 0a 46 c4 f2 b5 26 31 68 01 91 00 21 00 2c 11 60",
        ],
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "pal_memcpy": {
        "pattern": "03 00 52 e3 ???????? 03 c0 10 e2 08 00 00 0a ???????? 02 00 5c e3",
        "align": 4,
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_memset": {
        "pattern": "04 29 ???????? 10 f0 03 0c ?+ 5f ea c1 7c 24 bf 00 f8 01 2b 00 f8 01 2b 48 bf 00 f8 01 2b 70 47",
        "post_lookup": handlers.fixup_bios_symbol,
        "align": 2,
    },
}
