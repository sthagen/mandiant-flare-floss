# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import struct
import logging
import argparse
from typing import List, Iterable, Optional

import pefile

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 6


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
        raise ValueError("Invalid PE header")

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        """
        .data:0000000000770F20 3D 68 60 00 00 00+off_770F20      dq offset aString
        .data:0000000000770F28 15                                db  15h
        .data:0000000000770F29 00                                db    0
        """
        alignment = 0x10  # 16
        fmt = "<QQ"

        # See https://github.com/mandiant/flare-floss/issues/805#issuecomment-1590472813 for regex explanation
        combinedregex = re.compile(
            b"\x48\xba(........)|\x48\xb8(........)|\x81\x78\x08(....)|\x81\x79\x08(....)|\x66\x81\x78\x0c(..)|\x66\x81\x79\x0c(..)|\x80\x78\x0e(.)|\x80\x79\x0e(.)"
        )

        longstring64 = re.compile(b"\x48\x8d(?=.(....).(....))", re.DOTALL)

        longstring64_2 = re.compile(b"\x48\x83(?=.(.)(.){2,5}\x48\x8D.(....))", re.DOTALL)

        """
        .text:0000000000481745 48 C7 40 08 17 00 00 00       mov     qword ptr [rax+8], 17h
        .text:000000000048174D 48 8D 0D A2 AC 02 00          lea     rcx, aSyntaxErrorInP ; "syntax error in pattern"
        .text:0000000000481754 48 89 08                      mov     [rax], rcx
        """
        longstring64_3 = re.compile(b"\x48\xc7(?=..(.)...\x48\x8D.(....))", re.DOTALL)

        """
        .text:00000000004033CD B9 1C 00 00 00                mov     ecx, 1Ch
        .text:00000000004033D2 48 89 C7                      mov     rdi, rax
        .text:00000000004033D5 48 89 DE                      mov     rsi, rbx
        .text:00000000004033D8 31 C0                         xor     eax, eax
        .text:00000000004033DA 48 8D 1D C3 A1 0A 00          lea     rbx, aComparingUncom ; "comparing uncomparable type "
        .text:00000000004033E1 E8 5A 63 04 00                call    runtime_concatstring2
        """
        longstring64_4 = re.compile(b"\xb9(?=(.)...........\x48\x8D.(....))", re.DOTALL)

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        """
        .data:102A78D0 E3 9A 17 10                       dd offset aString
        .data:102A78D4 12                                db  12h
        """
        alignment = 0x8
        fmt = "<II"

        # See https://github.com/mandiant/flare-floss/issues/805#issuecomment-1590510957 for regex explanation
        combinedregex = re.compile(
            b"\x81\xf9(....)|\x81\x38(....)|\x81\x7d\x00(....)|\x81\x3B(....)|\x66\x81\xf9(..)|\x66\x81\x7b\x04(..)|\x66\x81\x78\x04(..)|\x66\x81\x7d\x04(..)|\x80\x7b\x06(.)|\x80\x7d\x06(.)|\x80\xf8(.)|\x80\x78\x06(.)",
            re.DOTALL,
        )
        longstring32 = re.compile(b"\x83(?=.(.).....\x8D\x05(....))", re.DOTALL)

    else:
        raise ValueError("unhandled architecture")

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            continue

        if section_name == ".text":
            # Extract go Build ID
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            # Build ID is a string that starts with "\xff\x20 Go build ID: " and ends with "\n"
            # FF 20 47 6F 20 62 75 69  6C 64 20 49 44 3A 20 22  . Go build ID: "
            # 36 4E 31 4D 77 6E 30 31  72 46 6E 41 51 4B 62 5A  6N1Mwn01rFnAQKbZ
            # 73 46 5A 32 2F 38 41 6B  75 63 4B 46 58 4D 49 54  sFZ2/8AkucKFXMIT
            # 63 51 52 49 75 55 5F 79  32 2F 62 76 4F 67 56 37  cQRIuU_y2/bvOgV7
            # 52 4D 54 72 77 73 7A 5A  39 57 7A 69 6C 64 2F 72  RMTrwszZ9Wzild/r
            # 33 31 50 47 70 61 6B 2D  48 77 36 4B 72 77 59 6E  31PGpak-Hw6KrwYn
            # 52 4E 73 22 0A 20 FF CC  CC CC CC CC CC CC CC CC  RNs". ..........

            build_id_regex = re.compile(b"(?<=\xff\x20)(.)*\x0A")

            for m in build_id_regex.finditer(section_data):
                addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va
                try:
                    string = m.group(0).decode("utf-8")
                    yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                except UnicodeDecodeError:
                    continue
                break

        if section_name == ".text":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            if alignment == 0x10:
                for m in longstring64.finditer(section_data):
                    format = "<I"
                    s_off = struct.unpack(format, m.group(1))[0]
                    s_size = struct.unpack(format, m.group(2))[0]

                    s_rva = s_off + m.start() + section_va + 7
                    addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va + 7
                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                        if string.isprintable() and string != "" and len(string) >= min_length:
                            yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        continue

                for m in longstring64_2.finditer(section_data):
                    s_off = struct.unpack("<I", m.group(3))[0]
                    s_size = struct.unpack("<B", m.group(1))[0]

                    s_rva = s_off + m.end() + section_va
                    addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va
                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                        if string.isprintable() and string != "" and len(string) >= min_length:
                            yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        continue

                for m in longstring64_3.finditer(section_data):
                    s_off = struct.unpack("<I", m.group(2))[0]
                    s_size = struct.unpack("<B", m.group(1))[0]

                    s_rva = s_off + m.end() + section_va + 13
                    addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va
                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                        if string.isprintable() and string != "" and len(string) >= min_length:
                            yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        continue

                for m in longstring64_4.finditer(section_data):
                    s_off = struct.unpack("<I", m.group(2))[0]
                    s_size = struct.unpack("<B", m.group(1))[0]

                    s_rva = s_off + m.end() + section_va + 19
                    addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va
                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                        if string.isprintable() and string != "" and len(string) >= min_length:
                            yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        continue

            else:
                for m in longstring32.finditer(section_data):
                    s_off = struct.unpack("<I", m.group(2))[0]
                    s_size = struct.unpack("<B", m.group(1))[0]

                    s_rva = s_off + m.end() + section_va
                    addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va

                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                        if string.isprintable() and string != "" and len(string) >= min_length:
                            yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        continue

        if section_name == ".rdata":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            blob_pattern = re.compile(b"(\x00|\x01)(.)", re.DOTALL)
            for m in blob_pattern.finditer(section_data):
                if m.group(2) != b"\x00":
                    data = section_data[m.end() : m.end() + m.group(2)[0]]
                    try:
                        data = data.decode("utf-8")
                        if str(data).isprintable() and data != "" and len(data) >= min_length:
                            addr = m.start() + pe.OPTIONAL_HEADER.ImageBase + section_va
                            yield StaticString(string=data, offset=addr, encoding=StringEncoding.ASCII)

                    except UnicodeDecodeError:
                        continue

        if section_name == ".text":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            for m in combinedregex.finditer(section_data):
                for i in range(1, 8):
                    try:
                        tmp_string = m.group(i)
                        if tmp_string != b"":
                            try:
                                decoded_string = tmp_string.decode("utf-8")
                                if decoded_string.isprintable() and len(decoded_string) >= min_length:
                                    addr = 0
                                    yield StaticString(
                                        string=decoded_string, offset=addr, encoding=StringEncoding.ASCII
                                    )
                            except UnicodeDecodeError:
                                pass
                    except AttributeError:
                        pass

        if section_name == ".rdata":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            blob_pattern = re.compile(b"\x67\x6F(\x2E|\x3A)\x62\x75\x69\x6C\x64\x69\x64\x00(.)*\x00\x00", re.DOTALL)
            for m in blob_pattern.finditer(section_data):
                t = m.group(0)
                for s in t.split(b"\x00"):
                    try:
                        x = s.decode("utf-8")
                        if x.isprintable() and x != "" and len(x) >= min_length:
                            addr = 0
                            yield StaticString(string=x, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        pass

        if section_name == ".idata":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            blob_pattern = re.compile(b"\x00\x00\x00(.)*\x00", re.DOTALL)
            for m in blob_pattern.finditer(section_data):
                t = m.group(0)
                for s in t.split(b"\x00"):
                    try:
                        x = s.decode("utf-8")
                        if x.isprintable() and x != "" and len(x) >= min_length:
                            addr = 0
                            yield StaticString(string=x, offset=addr, encoding=StringEncoding.ASCII)
                    except UnicodeDecodeError:
                        pass

        if section_name in (".rdata", ".data"):
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            for i in range(0, len(section_data) - alignment // 2, alignment // 2):
                try:
                    curr = section_data[i : i + alignment]
                    s_off, s_size = struct.unpack(fmt, curr)

                    if not s_off and not (1 <= s_size < 128):
                        continue

                    s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase

                    if not pe.get_section_by_rva(s_rva):
                        continue

                    addr = pe.OPTIONAL_HEADER.ImageBase + section_va + i

                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
                    except UnicodeDecodeError:
                        continue

                    if (
                        len(string) >= min_length and len(string) == s_size
                    ):  # if the string is greater than the minimum length
                        yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                except Exception as e:
                    logger.error(f"Error: {e}")
                    raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Go strings")
    parser.add_argument("path", help="file or path to analyze")
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
