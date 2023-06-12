# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import struct
import logging
import argparse
from typing import List, Iterable, Optional

import pefile

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def extract_go_strings(
    sample: str,
    min_length,
) -> Iterable[StaticString]:
    """
    Get Go strings from a PE file.
    Reference: https://github.com/mandiant/flare-floss/issues/779
    """

    try:
        pe = pefile.PE(sample)
    except pefile.PEFormatError as err:
        logger.debug(f"invalid PE file: {err}")
        sys.exit(0)

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        """
        .data:0000000000770F20 3D 68 60 00 00 00+off_770F20      dq offset aString
        .data:0000000000770F28 15                                db  15h
        .data:0000000000770F29 00                                db    0
        """
        alignment = 0x10  # 16
        fmt = "<QQ"  # The "<QQ" format string is used for packing and unpacking two unsigned long long (8-byte) values in little-endian byte order.

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        """
        .data:102A78D0 E3 9A 17 10                       dd offset aString
        .data:102A78D4 12                                db  12h
        """
        alignment = 0x8
        fmt = "<II"
    else:
        raise ValueError("unhandled architecture")

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            continue
        # print(section_name)
        if section_name in (".rdata", ".data"):
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            try:
                for i in range(0, len(section_data), alignment):
                    curr = section_data[i : i + alignment]
                    s_off, s_size = struct.unpack(fmt, curr)
                    if s_off and s_size:
                        s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase
                        if pe.get_section_by_rva(s_rva):
                            if 1 <= s_size < 128:
                                addr = pe.OPTIONAL_HEADER.ImageBase + section_va + i
                                try:
                                    string = pe.get_string_at_rva(s_rva, s_size).decode("ascii")
                                except UnicodeDecodeError:
                                    continue
                                # print(f"{section_name} 0x{addr:08x} 0x{s_off:08x} 0x{s_size:02x} {string}")
                                if len(string) >= min_length:
                                    yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
            except:
                pass

            try:
                for i in range(alignment // 2, len(section_data) - alignment // 2, alignment):
                    curr = section_data[i : i + alignment]
                    s_off, s_size = struct.unpack(fmt, curr)
                    if s_off and s_size:
                        s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase
                        if pe.get_section_by_rva(s_rva):
                            if 1 <= s_size < 128:
                                addr = pe.OPTIONAL_HEADER.ImageBase + section_va + i
                                try:
                                    string = pe.get_string_at_rva(s_rva, s_size).decode("ascii")
                                except UnicodeDecodeError:
                                    continue
                                # print(f"{section_name} 0x{addr:08x} 0x{s_off:08x} 0x{s_size:02x} {string}")
                                if len(string) >= min_length:
                                    yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
            except:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Go strings")
    parser.add_argument("path", help="file or path to analyze")
    # TODO -n no effect yet
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    args = parser.parse_args(args=argv)

    static_strings = extract_go_strings(args.path, min_length=args.min_length)

    for strings_obj in static_strings:
        string = strings_obj.string
        print(string)


if __name__ == "__main__":
    sys.exit(main())
