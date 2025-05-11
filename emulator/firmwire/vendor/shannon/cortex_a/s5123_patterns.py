import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS = {
    "boot_key_check": {
        "pattern": [
            "0880 1af091f9 e2a0 29f287f0 06f03efd 05f0d4f8 3aac 8021 2046 c1f3b4dd 1aa9 2046 1022 62f21ed1",  # G991BXXSCGXF5
            "0880 19f0a5fe e2a0 25f2f5f3 06f026fd 05f0bcf8 3aac 8021 2046 b8f3dddb 1aa9 2046 1022 56f2f4d3",  # G991BXXU5CVF3
        ],
        "offset_end": 0x0,
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "log_printf": {
        "pattern": [
            "83b0 2de9f0?? ??b0 0df14c0c 0024",  # oriole-sq3a.220705.004
            "83b0 2de9f0?? ??b0 4af29018 0df14c0c 0024",  # G981BXXSKHXEA
            "83b0 2de9f0?? ??b0 4bf68828 0df14c0c 0024",  # G991BXXSCGXF5
            "83b0 2de9f04f 8ab0 45f2ec68 0df14c0c 0024",  # G991BXXU5CVF3
        ],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": [
            "f0b5 81b0 0446 fff72cef 0546 fff728ef 45f64026 c4f60506 7179 8842",  # oriole-sq3a.220705.004
            "f0b5 81b0 0446 fff7ecea 0546 fff7eaea 49f28036 c4f23046 7179 8842",  # G981BXXSKHXEA
            "f0b5 81b0 0446 00f0d8e8 0546 00f0d4e8 4bf60056 c4f21256 7179 8842",  # G991BXXSCGXF5
            "f0b5 81b0 0446 00f0dae8 0546 00f0d6e8 41f24066 c4f21056 7179 8842",  # G991BXXU5CVF3
            "f0b5 81b0 0446 fff722ef 0546 fff71eef 4af24046 c4f61c06 7179 8842",  # oriole-ap2a.240905.003.f1
        ],
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
    "pal_MemAlloc": {
        "pattern": [
            "2de9f04f 85b0 9a46 9146 0c46 8046 29b1 14f00305 18bf c5f10405 11e0",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "2de9f04f 85b0 0c46 9a46 9146 8046 2cb1 14f00305 18bf c5f10405 11e0",  # G981BXXSKHXEA
            "2de9f04f 85b0 4bf68825 8046 0c46 9a46 9146 c4f2b625 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0",  # G991BXXSCGXF5
            "2de9f04f 85b0 45f2ec65 8046 0c46 9a46 9146 c4f2b525 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0",  # G991BXXU5CVF3
        ],
    },
    "pal_MemFree": {
        "pattern": [
            "2de9f04f 87b0 cde90312 8146 a9f2eac3 8246 a8f20ec1 4ef60035 c4f6e005 6979 8842",  # oriole-sq3a.220705.004
            "2de9f04f 87b0 1546 0491 0646 43f2d6c7 8346 3df246c6 43f2c059 c4f20d59 99f80510 8842",  # G981BXXSKHXEA
            "2de9f04f 89b0 4bf6882a cde90421 0746 c4f2b62a daf80000 0890 6af2f0c5 0646 63f2f0c0 4ef6800b c4f2cb5b 9bf80510 8842",  # G991BXXSCGXF5
            "2de9f04f 89b0 45f2ec6a cde90421 0746 c4f2b52a daf80000 0890 5ff268c7 0646 58f2eec1 4ff6005b c4f2c85b 9bf80510 8842",  # G991BXXU5CVF3
            "2de9f04f 87b0 cde90312 8146 c2f2c8c0 8246 c0f2acc4 4ff60005 c4f6fa05 6979 8842",  # oriole-ap2a.240905.003.f1
        ],
    },
    "pal_Sleep": {
        "pattern": [
            "0121 3cf73b9f",  # oriole-sq3a.220705.004
            "0121 15f73ab7",  # G981BXXSKHXEA
            "0121 e0f6089e",  # G991BXXSCGXF5
            "0121 e9f61d9d",  # G991BXXU5CVF3
            "0121 c6f61f9a",  # oriole-ap2a.240905.003.f1
        ],
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "10b5 82b0 8c46 0021 1446 002a ccf80010 00d0 2170",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "10b5 82b0 8c46 0021 1446 002c ccf80010 00d0 2170",  # G981BXXSKHXEA
            "70b5 82b0 4bf68826 1446 0a46 c4f2b626 3168 0191 0021 002c 1160 00d0 2170",  # G991BXXSCGXF5
            "70b5 82b0 45f2ec66 1446 0a46 c4f2b526 3168 0191 0021 002c 1160 00d0 2170",  # G991BXXU5CVF3
        ],
        "soc_match": ["S5123", "S5123AP"],
        "required": True,
    },
    "pal_MsgSendTo": {
        "pattern": [
            "2de9f041 1546 0c46 0646 b0f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "f0b5 81b0 0646 1546 0c46 b6f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G981BXXSKHXEA
            "2de9f043 81b0 0646 9046 8946 b6f57a7f 13db 44f67070 44f61d61 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G991BXXSCGXF5
            "2de9f047 82b0 0646 9146 8a46 b6f57a7f 15db 4ef6e420 42f26521 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G991BXXU5CVF3
        ]
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 0068 80b1 6ef798d1 0446 4ff6ff70 0442 0ad0 40f2ea71 20b2",  # oriole-sq3a.220705.004
            "10b5 0068 80b1 57f6c6d1 0446 4ff6ff70 0442 0ad0 45f6b801 20b2",  # G981BXXSKHXEA
            "10b5 0068 80b1 bff7f9d2 0446 4ff6ff70 0442 0ad0 44f67a51 20b2",  # G991BXXSCGXF5
            "10b5 0068 80b1 c5f715d1 0446 4ff6ff70 0442 0ad0 42f2c211 20b2",  # G991BXXU5CVF3
            "10b5 0068 80b1 03f7d1d6 0446 4ff6ff70 0442 0ad0 41f66b31 20b2",  # oriole-ap2a.240905.003.f1
        ],
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": lambda data, offset: 0xc3a5,
    },
    "SYM_EVENT_GROUP_LIST": {
        "lookup": handlers.find_event_group_list,
    },
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "SYM_CUR_TASK_ID": {"lookup": handlers.find_current_task_ptr},
    "SYM_CUR_TASK_PTR": {"lookup": handlers.find_current_task_ptr_a},
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
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
