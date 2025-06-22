#!/usr/bin/env python3
# Copyright (c) 2023, Grant Hernandez (https://github.com/grant-h)
# SPDX-License-Identifier: MIT
#
# Modified work:
# Copyright (c) 2025, [Your Name]
# SPDX-License-Identifier: BSD-3-Clause
#
# This file contains modifications to the original MIT-licensed work.
# The original license terms continue to apply to the original portions.
#
# A python script to decode Samsung cpcrash_cp_btl_dump_umts_*.log files that
# are generated during Shannon modem dumps / crashes. Check out the 'BTL' task
# in the modem for hints as how this file is generated.

import argparse
import re
import struct
import sys
import traceback

from typing import Tuple

import utils


BTL_MIN_HEADER_SIZE = 0x30
SLOG_MAGIC = b"SLOG"
CBUF_MAGIC = b"CBUF"
BUFN_MAGIC = [b"BUF1", b"BUF2", b"BUF3", b"BUF4"]
FORMAT_SPECIFIER = re.compile('%?%[0-9lh.]*[a-zA-Z]')


class BadFileError(Exception):
    def __init__(self, message):
        super(BadFileError, self).__init__(message)


class BTL:
    def __init__(self, modem_data: memoryview, btl_data: memoryview):
        self._modem_data = modem_data
        self._btl_data = btl_data
        self._btl_version = None

    def modem_read_from(self, address, size, base=0x40010000) -> memoryview:
        offset = address - base

        if offset < 0:
            raise ValueError(
                "Modem read address 0x%08x is invalid. This is likely the "
                "result of a mismatched modem.bin/*.BTL file pair" % (address))

        return self._modem_data[offset:offset+size]

    def modem_read_cstring_from(self, address, base=0x40010000) -> str:
        st = b""
        i = 0

        byte = self.modem_read_from(address, 1, base).tobytes()
        while byte != b'\x00':
            st += byte
            i += 1
            byte = self.modem_read_from(address + i, 1, base).tobytes()

        return st.decode('ascii', 'ignore')

    def extract_version_str(self) -> str:
        btl_version = self._btl_data[8:0xc]
        return btl_version.tobytes().decode()

    def verify_header(self):
        btl_magic = self._btl_data[:4]

        if btl_magic != b"BTL:":
            raise BadFileError(f"Invalid BackTraceLog (BTL) magic {btl_magic}")

        if len(self._btl_data) < BTL_MIN_HEADER_SIZE:
            raise BadFileError("BTL size is smaller than minium length")

    def process_btl(self):
        self.verify_header()

        btl_version = self.extract_version_str()
        self._btl_version = btl_version

        if btl_version == "1100":
            self._process_btl_1100()
        elif btl_version == "1300":
            self._process_btl_1300()
        else:
            raise BadFileError(
                "Unsupported BTL version '%s' (expected '%s' or '%s')"
                % (btl_version, "1100", "1300"))

    @staticmethod
    def is_likely_slog(data):
        return len(data) > 0x10 and data[:4] == SLOG_MAGIC

    def _process_btl_1100(self):
        offset = 0xc
        sub_buffer_count1, sub_buffer_count2, *buf_starts = \
            struct.unpack("<6I", self._btl_data[offset: offset + 6 * 4])
        offset += 6 * 4

        for buf_start in buf_starts:
            self._process_bufn(self._btl_data[buf_start:], 0xc)

    def _process_btl_1300(self):
        offset = 0x14
        sub_buffer_count1, sub_buffer_count2, *buf_starts = \
            struct.unpack("<6I", self._btl_data[offset: offset + 6 * 4])
        offset += 6 * 4

        for buf_start in buf_starts:
            self._process_bufn(self._btl_data[buf_start:], 0x1c)

        version_size, date_size = \
            struct.unpack("<2H", self._btl_data[offset: offset + 2 * 2])
        version = utils.read_cstring(self._btl_data[0x30: 0x30 + version_size])
        build_date = utils.read_cstring(self._btl_data[0x60: 0x60 + date_size])

        offset = 0x80
        cbuf_magic, cbuf_end_offset, cbuf_size = \
            struct.unpack("<3I", self._btl_data[offset: offset + 3 * 4])
        offset += 3 * 4

        slog_start = self._btl_data[offset + 0x1e:]
        while self.is_likely_slog(slog_start):
            decompressed, skip_amount = \
                self._process_slog_compressed(slog_start)
            print(f"skip_amount={skip_amount:#x}", file=sys.stderr)
            self._process_slog(decompressed)
            slog_start = slog_start[skip_amount:]
        print("version: {}".format(version), file=sys.stderr)
        print("build_date: {}".format(build_date), file=sys.stderr)

    def _process_bufn(self, data: memoryview, slog_offset: int):
        bufn_magic = data[:4].tobytes()

        if bufn_magic not in BUFN_MAGIC:
            raise BadFileError(
                "Unexpected BUFn magic %s (need one of %s)"
                % (bufn_magic, BUFN_MAGIC))

        print(f"Processing {bufn_magic}...", file=sys.stderr)

        _, buf_len = struct.unpack("2I", data[4:0xc])

        try:
            self._process_slog(data[slog_offset: slog_offset + buf_len])
        except ValueError as e:
            print(traceback.format_exc())
            raise BadFileError("Error when decoding SLOG frames: %s" % e)

    def _process_slog_compressed(self, data):
        if not self.is_likely_slog(data):
            raise BadFileError("Invalid SLOG magic or header is too small")

        compressed_size = struct.unpack("I", data[4:8])[0]
        uncompressed_size = struct.unpack("I", data[0xc:0x10])[0]

        if len(data)-0x10 < compressed_size:
            raise BadFileError(
                "Truncated SLOG (header requests %u bytes, but only have %u "
                "left)" % (compressed_size, len(data)-0x10))

        dst_buf = bytearray()
        utils.lz4_decompress_sequences(
            data[0x10: 0x10 + compressed_size], dst_buf)

        if len(dst_buf) != uncompressed_size:
            raise BadFileError(
                "SLOG head uncompressed size does match file size (expected %u"
                ", got %u)" % (uncompressed_size, len(dst_buf)))

        # output buffer, skip amount
        return dst_buf, compressed_size+0x10

    def _extract_flags_uptime(self, data: memoryview) -> tuple:
        if self._btl_version == "1100":
            return struct.unpack("=HBBBIB", data)
        if self._btl_version == "1300":
            return struct.unpack("=HBBBIBB", data)

    def _process_slog(self, data: memoryview):
        ptr = data

        while len(ptr) > 4:
            eptr = ptr
            slog_entry_header = eptr[0:3]
            start_of_frame, size = struct.unpack("=BH", slog_entry_header)

            if start_of_frame != 0x7f:
                raise BadFileError("Invalid start-of-frame")

            # move to next slog entry
            ptr = ptr[2 + size:]

            eptr = eptr[4: size + 2]  # skip header and padding
            sub_length = struct.unpack("H", eptr[:2])[0]  # 2-byte sub length

            if sub_length != len(eptr)-1:
                raise BadFileError(
                    "Entry sub-length does not match entry length")

            if eptr[-1] != 0x7e:
                raise BadFileError("Invalid end-of-frame")

            eptr = eptr[2:]

            if self._btl_version == "1100":
                unk2 = eptr[:10]
                flag1, flag2, flag3, flag4, uptime, flag5 = \
                    struct.unpack("=HBBBIB", unk2)
                eptr = eptr[10:]
            elif self._btl_version == "1300":
                unk2 = eptr[:11]
                flag1, flag2, flag3, flag4, uptime, flag5, flag6 = \
                    struct.unpack("=HBBBIBB", unk2)
                eptr = eptr[11:]

            entry = eptr
            trace_entry_p = struct.unpack("I", entry[:4])[0]
            entry = entry[6:]
            entry = entry[1:]

            try:
                te_data = self.modem_read_from(trace_entry_p, 4 * 7)
            except ValueError:
                continue
            if len(te_data) != 7 * 4:
                continue

            te_magic, _, _, _, te_fmt, te_linenum, te_file = \
                struct.unpack("7I", te_data)
            if te_magic != 0x3a544244:
                continue

            fmt = self.modem_read_cstring_from(te_fmt)
            file_name = self.modem_read_cstring_from(te_file)

            try:
                formatted = self._vsprintf(fmt, entry)
                print("[{:.2f}] 0x{:08x}: [{}:{}] {}".format(
                    uptime, trace_entry_p, file_name, te_linenum,
                    formatted.rstrip()))
            except ValueError as e:
                print("[ERROR %s]: %s" % (str(e), fmt))

    def _vsprintf(self, fmt, entry):
        argv_resolved = []

        res = FORMAT_SPECIFIER.findall(fmt)

        for i, r in enumerate(res):
            if r[0] == '%' and r[1] == '%':
                continue

            arg_size = 4
            arg = struct.unpack("I", entry[:4])[0]

            if r[-1] == 's':
                if arg == 0:
                    arg = "(NULL)"
                else:
                    # TODO: make variable length
                    arg = self.modem_read_cstring_from(arg)
            elif r[-1] == 'C':
                fmt = fmt.replace(r, r[:-1] + "c")
            elif r[-1] == 'p':
                fmt = fmt.replace(r, "0x%08x")

            argv_resolved += [arg]
            entry = entry[arg_size:]

        try:
            formatted = fmt % tuple(argv_resolved[:len(res)])
        except (TypeError, ValueError):
            formatted = "FORMAT ERROR: [{}] [{}] [{}]".format(
                str(fmt), str(res), str(argv_resolved))

        return formatted


def get_args():
    parser = argparse.ArgumentParser()
    # this is the MAIN TOC entry in the overall modem.bin
    parser.add_argument(
        "modem_file", help="Path to the MAIN section extracted from modem.bin."
        " Required to resolve debugging strings.")
    parser.add_argument("cplog_file", help="Path to the BTL log file.")

    return parser.parse_args()


def load_files(modem_file, cplog_file) -> Tuple[memoryview, memoryview]:
    """
    Returns the content of modem_main and cpcrash_cp_btl_* file
    """
    try:
        modem_data = memoryview(open(modem_file, "rb").read())
    except IOError:
        modem_data = None
    try:
        btl_data = memoryview(open(cplog_file, "rb").read())
    except IOError:
        btl_data = None

    return modem_data, btl_data


def main():
    args = get_args()

    modem_data, btl_data = load_files(args.modem_file, args.cplog_file)

    if modem_data is None:
        print("Unable to open modem image: {}".format(args.modem_file))
        return 1
    if btl_data is None:
        print("Unable to open BTL file: {}".format(args.cplog_file))
        return 1

    btl_util = BTL(modem_data, btl_data)
    btl_util.process_btl()

    return 0


if __name__ == "__main__":
    sys.exit(main())
