from avatar2 import *

from . import LoggingPeripheral


class Unknown5Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x84 or offset == 0x104 or offset == 0x184 or offset == 0xb84:
            # something != 0
            value = 1
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class Unknown6Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x4:
            value = 1
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class Unknown7Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x11c:
            value = 3
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write