import hashlib
import struct

from typing import Tuple

from .consts import *
from firmwire.vendor.shannon.pal_structs import PALQueue, PALMsg


class SAEL3QItem:
    PLD_PATTERN = {
        SAEL3MsgType.SAEMM_EXT: "<IHHI",
    }
    UID_PATTERN = {
        SAEL3MsgType.SAEMM_EXT: "<HIHH",
    }

    def __init__(
            self,
            qitem: PALMsg,
    ):
        self._src_queue = qitem.src_queue
        self._dst_queue = qitem.dst_queue
        self._size = qitem.size
        self._msg_id = qitem.msg_id
        self._data = qitem.data
        self._msg_type: SAEL3MsgType = SAEL3MsgType.UNKNOWN
        self._uid = ""

    @property
    def pld_pattern(self) -> str:
        if self._msg_type in self.PLD_PATTERN.keys():
            return self.PLD_PATTERN[self._msg_type]
        return ""

    @property
    def uid_pattern(self) -> str:
        if self._msg_type in self.UID_PATTERN.keys():
            return self.UID_PATTERN[self._msg_type]
        return ""

    @property
    def msg_id(self) -> MsgId:
        return self._msg_id

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def msg_type(self) -> SAEL3MsgType:
        return self._msg_type

    @msg_type.setter
    def msg_type(self, t: SAEL3MsgType):
        self._msg_type = t

    @property
    def uid(self) -> Uid:
        return self._uid

    @uid.setter
    def uid(self, uid: Uid):
        self._uid = uid
