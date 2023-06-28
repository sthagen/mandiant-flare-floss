# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import struct
import logging
import pathlib
import argparse
from typing import List, Iterable, Optional
from itertools import chain

import pefile

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 6


def extract_strings_from_import_data(pe: pefile.PE) -> Iterable[StaticString]:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        # This is a Go binary, but it doesn't have an import table
        return

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name is not None:
                addr = imp.name_offset
                yield StaticString(string=imp.name.decode("ascii"), offset=addr, encoding=StringEncoding.ASCII)


def extract_build_id(section_data, min_length) -> Iterable[StaticString]:
    # Build ID is a string that starts with "\xff\x20 Go build ID: " and ends with "\n"
    # FF 20 47 6F 20 62 75 69  6C 64 20 49 44 3A 20 22  . Go build ID: "
    # 36 4E 31 4D 77 6E 30 31  72 46 6E 41 51 4B 62 5A  6N1Mwn01rFnAQKbZ
    # 73 46 5A 32 2F 38 41 6B  75 63 4B 46 58 4D 49 54  sFZ2/8AkucKFXMIT
    # 63 51 52 49 75 55 5F 79  32 2F 62 76 4F 67 56 37  cQRIuU_y2/bvOgV7
    # 52 4D 54 72 77 73 7A 5A  39 57 7A 69 6C 64 2F 72  RMTrwszZ9Wzild/r
    # 33 31 50 47 70 61 6B 2D  48 77 36 4B 72 77 59 6E  31PGpak-Hw6KrwYn
    # 52 4E 73 22 0A 20 FF CC  CC CC CC CC CC CC CC CC  RNs". ..........

    build_id_regex = re.compile(b"(?<=\xff\x20)(?P<buildid>(.)*)\x0A")

    s = re.search(build_id_regex, section_data)
    if s:
        addr = s.start()
        binary_string = s.group("buildid")

        try:
            string = StaticString.from_utf8(binary_string, addr, min_length)
            yield string
        except ValueError:
            pass

        return string


def extract_stackstring(extract_stackstring_pattern, section_data, min_length) -> Iterable[StaticString]:
    for m in extract_stackstring_pattern.finditer(section_data):
        for i in range(1, 8):
            try:
                binary_string = m.group(i)
                if binary_string != b"":
                    addr = m.start()
                    try:
                        string = StaticString.from_utf8(binary_string, addr, min_length)
                        yield string
                    except ValueError:
                        pass
            except AttributeError:
                break


def extract_reflection_strings(pe: pefile.PE, section_data, section_va, min_length) -> Iterable[StaticString]:
    # Extract string blob in .rdata section
    # The data looks like <start_byte><length><string>  <start_byte><length><string>...
    # <start_byte> is 0x00 or 0x01 or 0x02 or 0x03

    # Data:-
    """
    0048E620  5B 34 5D 75 69 6E 74 38  00 09 2A 5B 38 5D 69 6E  [4]uint8..*[8]in
    0048E630  74 33 32 00 09 2A 5B 38  5D 75 69 6E 74 38 00 09  t32..*[8]uint8..
    0048E640  2A 5B 5D 73 74 72 69 6E  67 00 09 2A 5B 5D 75 69  *[]string..*[]ui
    0048E650  6E 74 31 36 00 09 2A 5B  5D 75 69 6E 74 33 32 00  nt16..*[]uint32.
    0048E660  09 2A 5B 5D 75 69 6E 74  36 34 00 09 2A 63 68 61  .*[]uint64..*cha
    0048E670  6E 20 69 6E 74 01 09 41  6E 6F 6E 79 6D 6F 75 73  n int..Anonymous
    0048E680  01 09 43 61 6C 6C 53 6C  69 63 65 01 09 43 6C 65  ..CallSlice..Cle
    0048E690  61 72 42 75 66 73 01 09  43 6F 6E 6E 65 63 74 45  arBufs..ConnectE
    0048E6A0  78 01 09 46 74 72 75 6E  63 61 74 65 01 09 49 6E  x..Ftruncate..In
    0048E6B0  74 65 72 66 61 63 65 01  09 4E 75 6D 4D 65 74 68  terface..NumMeth
    0048E6C0  6F 64 01 09 50 72 65 63  69 73 69 6F 6E 01 09 52  od..Precision..R
    """

    # The blob start like 00 00 <data> and ends like this:
    """
    0000000000492A40  6C 65 63 74 2E 53 74 72  75 63 74 46 69 65 6C 64  lect.StructField
    0000000000492A50  2C 20 62 6F 6F 6C 29 00  00 00 00 00 00 00 00 00  , bool).........
    0000000000492A60  08 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  ................
    """

    # Get the blob
    blob_end_pattern = re.compile(b"\x00{8}.\x00{7}.\x00{7}")
    blob_end = re.search(blob_end_pattern, section_data[2:])
    if not blob_end:
        return
    blob = section_data[2 : blob_end.start()]

    # Extract strings from the blob
    blob_pattern = re.compile(b"(\x00|\x01|\x02|\x03)(?P<string_length>.)", re.DOTALL)
    for m in blob_pattern.finditer(blob):
        if m.group("string_length") != b"\x00":
            try:
                addr = pe.get_offset_from_rva(m.start() + section_va + 4)
                binary_string = blob[m.end() : m.end() + m.group("string_length")[0]]
                try:
                    string = StaticString.from_utf8(binary_string, addr, min_length)
                    yield string
                except ValueError:
                    pass
            except pefile.PEFormatError:
                pass


def extract_string_blob2(pe: pefile.PE, section_data, section_va, min_length) -> Iterable[StaticString]:
    # Extract string blob in .rdata section that starts with "go:buildid" or "go.buildid"
    """
    67 6F 3A 62 75 69 6C 64  69 64 00 69 6E 74 65 72  go:buildid.inter
    6E 61 6C 2F 63 70 75 2E  49 6E 69 74 69 61 6C 69  nal/cpu.Initiali
    7A 65 00 69 6E 74 65 72  6E 61 6C 2F 63 70 75 2E  ze.internal/cpu.
    70 72 6F 63 65 73 73 4F  70 74 69 6F 6E 73 00 69  processOptions.i
    6E 74 65 72 6E 61 6C 2F  63 70 75 2E 69 6E 64 65  nternal/cpu.inde
    78 42 79 74 65 00 69 6E  74 65 72 6E 61 6C 2F 63  xByte.internal/c
    """

    # Get the blob
    blob_start_pattern = re.compile(b"go(\.|:)buildid\x00")
    blob_start = re.search(blob_start_pattern, section_data)
    if not blob_start:
        return
    blob = section_data[blob_start.start() :]
    blob_end_pattern = re.compile(b"\x00{2}")
    blob_end = re.search(blob_end_pattern, blob)
    if not blob_end:
        return
    blob = blob[: blob_end.start()]

    # Extract strings from the blob
    length = 0
    for binary_string in blob.split(b"\x00"):
        addr = pe.get_offset_from_rva(blob_start.start() + section_va + length)
        length += len(binary_string) + 1
        try:
            string = StaticString.from_utf8(binary_string, addr, min_length)
            yield string
        except ValueError:
            pass


def extract_file_path_strings(pe: pefile.PE, section_data, section_va, min_length) -> Iterable[StaticString]:
    # 004D14D0  00 1C 00 00 5F 1C 00 00  00 00 00 00 00 00 00 00  ...._...........
    # 004D14E0  2F 75 73 72 2F 6C 6F 63  61 6C 2F 67 6F 2F 73 72  /usr/local/go/sr
    # 004D14F0  63 2F 69 6E 74 65 72 6E  61 6C 2F 63 70 75 2F 63  c/internal/cpu/c
    # 004D1500  70 75 2E 67 6F 00 2F 75  73 72 2F 6C 6F 63 61 6C  pu.go./usr/local
    # 004D1510  2F 67 6F 2F 73 72 63 2F  69 6E 74 65 72 6E 61 6C  /go/src/internal

    # Get the blob start
    blob_start_pattern = re.compile(b"\x00{8}/usr/")
    blob_start = re.search(blob_start_pattern, section_data)
    if not blob_start:
        return
    blob = section_data[blob_start.start() + 8 :]

    blob_end_pattern = re.compile(b"\x00{2}")
    blob_end = re.search(blob_end_pattern, blob)
    if not blob_end:
        return
    blob = blob[: blob_end.start()]

    # Extract strings from the blob
    length = 0
    for binary_strin in blob.split(b"\x00"):
        addr = pe.get_offset_from_rva(blob_start.start() + section_va + length)
        length += len(binary_strin) + 1
        try:
            string = StaticString.from_utf8(binary_strin, addr, min_length)
            yield string
        except ValueError:
            pass


def extract_strings_referenced_by_string_table(pe: pefile.PE, section_data, min_length, arch) -> Iterable[StaticString]:
    # Extract strings from string table in .rdata section
    # .data:00537B40                 dd offset unk_4A1E3C
    # .data:00537B44                 dd    4
    # .data:00537B48                 dd offset unk_4A21C2
    # .data:00537B4C                 dd    6

    if arch == "amd64":
        size = 0x10
        fmt = "<QQ"
    else:
        size = 0x8
        fmt = "<II"

    for addr in range(0, len(section_data) - size // 2, size // 2):
        try:
            curr = section_data[addr : addr + size]
            s_off, s_size = struct.unpack(fmt, curr)

            if not s_off and not (1 <= s_size < 128):
                continue

            s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase

            if not pe.get_section_by_rva(s_rva):
                continue

            binary_string = pe.get_string_at_rva(s_rva, s_size)

            addr = pe.get_offset_from_rva(s_rva)

            try:
                string = StaticString.from_utf8(binary_string, addr, min_length)
                yield string
            except ValueError:
                pass

        except Exception as e:
            logger.error(f"Error: {e}")
            raise


def extract_strings_referenced_by_code(
    pe: pefile.PE, section_data, section_va, min_length, pattern, arch, regex_offset: Optional[int] = 0
) -> Iterable[StaticString]:
    for m in pattern.finditer(section_data):
        s_off = struct.unpack("<I", m.group("offset"))[0]
        s_size = struct.unpack("<B", m.group("size"))[0]

        if arch == "amd64":
            # .text:000000000048FF87 48 8D 1D 51 DC 01 00                          lea     rbx, unk_4ADBDF
            # .rdata:00000000004ADBDF unk_4ADBDF      db  42h ; B             ; DATA XREF: main_main+1E7↑o
            # To obtain the correct offset, we need to add the bytes we receive, which are 00 01 DC 51, to the current offset.

            s_rva = s_off + m.start() + section_va + regex_offset

        elif arch == "386":
            # .text:0048CED8 8D 05 3A 49 4A 00                             lea     eax, unk_4A493A
            # .rdata:004A493A unk_4A493A      db  42h ; B             ; DATA XREF: main_main+1C8↑o
            # The correct offset is determined by the bytes we receive, which are 00 4A 49 3A.

            s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase

        if not pe.get_section_by_rva(s_rva):
            continue
        addr = pe.get_offset_from_rva(s_rva)

        binary_string = pe.get_string_at_rva(s_rva, s_size)
        try:
            string = StaticString.from_utf8(binary_string, addr, min_length)
            yield string
        except ValueError:
            pass


def extract_go_strings(
    sample: pathlib.Path,
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
        raise ValueError(f"Invalid PE file: {err}")

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        """
        .data:0000000000770F20 3D 68 60 00 00 00+off_770F20      dq offset aString
        .data:0000000000770F28 15                                db  15h
        .data:0000000000770F29 00                                db    0
        """
        arch = "amd64"

        """
        .text:000000000048FFA9 48 83 FB 0F                                   cmp     rbx, 0Fh
        .text:000000000048FFAD 75 69                                         jnz     short loc_490018
        .text:000000000048FFAF 48 BA 50 61 73 73 77 6F 72 64                 mov     rdx, 64726F7773736150h
        .text:000000000048FFB9 48 39 10                                      cmp     [rax], rdx
        .text:000000000048FFBC 75 5A                                         jnz     short loc_490018
        .text:000000000048FFBE 81 78 08 69 73 50 72                          cmp     dword ptr [rax+8], 72507369h
        .text:000000000048FFC5 75 51                                         jnz     short loc_490018
        .text:000000000048FFC7 66 81 78 0C 61 6E                             cmp     word ptr [rax+0Ch], 6E61h
        .text:000000000048FFCD 75 49                                         jnz     short loc_490018
        .text:000000000048FFCF 80 78 0E 6B                                   cmp     byte ptr [rax+0Eh], 6Bh ; 'k'
        .text:000000000048FFD3 75 43                                         jnz     short loc_490018
        """
        extract_stackstring_pattern = re.compile(
            b"\x48\xba(........)|\x48\xb8(........)|\x81\x78\x08(....)|\x81\x79\x08(....)|\x66\x81\x78\x0c(..)|\x66\x81\x79\x0c(..)|\x80\x78\x0e(.)|\x80\x79\x0e(.)"
        )

        # The "?=" in the regular expression is a lookahead assertion that allows us to match a specific pattern without including it in the actual match.
        # The "re.DOTALL" flag ensures that the dot "." in the regular expression matches any character, including newline characters.

        """
        .text:0000000000426BC8 48 8D 05 0C 5B 08 00          lea     rax, aPageallocOutOf ; "pageAlloc: out of memory"
        .text:0000000000426BCF BB 18 00 00 00                mov     ebx, 18h
        .text:0000000000426BD4 E8 67 CB 00 00                call    runtime_throw
        """
        extract_longstring64 = re.compile(b"\x48\x8d(?=.(?P<offset>....).(?P<size>.))", re.DOTALL)

        """
        .text:000000000048E780 	48 83 FB 13 	             cmp rbx, 13h
        .text:000000000048E784 	75 13 	                     jnz short loc_48E799
        .text:000000000048E786 	48 89 D9 	                 mov rcx, rbx
        .text:000000000048E789 	48 8D 1D E1 B5 01 00 	     lea rbx, unk_4A9D71
        """
        extract_longstring64_2 = re.compile(b"\x48\x83(?=.(?P<size>.)(.){2,5}\x48\x8D.(?P<offset>....))", re.DOTALL)

        """
        .text:0000000000481745 48 C7 40 08 17 00 00 00       mov     qword ptr [rax+8], 17h
        .text:000000000048174D 48 8D 0D A2 AC 02 00          lea     rcx, aSyntaxErrorInP ; "syntax error in pattern"
        .text:0000000000481754 48 89 08                      mov     [rax], rcx
        """
        extract_longstring64_3 = re.compile(b"\x48\xc7(?=..(?P<size>.)...\x48\x8D.(?P<offset>....))", re.DOTALL)

        """
        .text:00000000004033CD B9 1C 00 00 00                mov     ecx, 1Ch
        .text:00000000004033D2 48 89 C7                      mov     rdi, rax
        .text:00000000004033D5 48 89 DE                      mov     rsi, rbx
        .text:00000000004033D8 31 C0                         xor     eax, eax
        .text:00000000004033DA 48 8D 1D C3 A1 0A 00          lea     rbx, aComparingUncom ; "comparing uncomparable type "
        .text:00000000004033E1 E8 5A 63 04 00                call    runtime_concatstring2
        """
        extract_longstring64_4 = re.compile(b"\xb9(?=(?P<size>.)...........\x48\x8D.(?P<offset>....))", re.DOTALL)

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        """
        .data:102A78D0 E3 9A 17 10                       dd offset aString
        .data:102A78D4 12                                db  12h
        """
        arch = "386"

        """
        .text:0048CED3 75 6D                                         jnz     short loc_48CF42
        .text:0048CED5 81 7D 00 50 61 73 73                          cmp     dword ptr [ebp+0], 73736150h
        .text:0048CEDC 75 64                                         jnz     short loc_48CF42
        .text:0048CEDE 66 81 7D 04 77 6F                             cmp     word ptr [ebp+4], 6F77h
        .text:0048CEE4 75 5C                                         jnz     short loc_48CF42
        .text:0048CEE6 80 7D 06 72                                   cmp     byte ptr [ebp+6], 72h ; 'r'
        .text:0048CEEA 75 56                                         jnz     short loc_48CF42
        """
        extract_stackstring_pattern = re.compile(
            b"\x81\xf9(....)|\x81\x38(....)|\x81\x7d\x00(....)|\x81\x3B(....)|\x66\x81\xf9(..)|\x66\x81\x7b\x04(..)|\x66\x81\x78\x04(..)|\x66\x81\x7d\x04(..)|\x80\x7b\x06(.)|\x80\x7d\x06(.)|\x80\xf8(.)|\x80\x78\x06(.)",
            re.DOTALL,
        )

        # The "?=" in the regular expression is a lookahead assertion that allows us to match a specific pattern without including it in the actual match.
        # The "re.DOTALL" flag ensures that the dot "." in the regular expression matches any character, including newline characters.

        """
        .text:0048CED0 83 F8 13                                      cmp     eax, 13h
        .text:0048CED3 75 23                                         jnz     short loc_48CEF8
        .text:0048CED5 89 2C 24                                      mov     [esp+0B0h+var_B0], ebp
        .text:0048CED8 8D 05 3A 49 4A 00                             lea     eax, unk_4A493A
        .text:0048CEDE 89 44 24 04                                   mov     [esp+0B0h+var_AC], eax
        .text:0048CEE2 C7 44 24 08 13 00 00 00                       mov     [esp+0B0h+var_A8], 13h
        """
        extract_longstring32 = re.compile(b"\x83(?=.(?P<size>.).....\x8D\x05(?P<offset>....))", re.DOTALL)

        """
        .text:00403276 8D 15 64 63 4A 00                             lea     edx, unk_4A6364
        .text:0040327C 89 54 24 04                                   mov     [esp+1Ch+var_18], edx
        .text:00403280 C7 44 24 08 1C 00 00 00                       mov     [esp+1Ch+var_14], 1Ch
        """
        extract_longstring32_2 = re.compile(b"\x8D.(?=(?P<offset>....)........(?P<size>.))", re.DOTALL)

        """
        .text:0047EACA C7 40 0C 19 00 00 00                          mov     dword ptr [eax+0Ch], 19h
        .text:0047EAD1 8D 0D 36 56 4A 00                             lea     ecx, unk_4A5636
        .text:0047EAD7 89 48 08                                      mov     [eax+8], ecx
        """
        extract_longstring32_3 = re.compile(b"\xc7.(?=.(?P<size>.)...\x8D.(?P<offset>....))", re.DOTALL)
    else:
        raise ValueError("unhandled architecture")

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            continue

        section_va = section.VirtualAddress
        section_size = section.SizeOfRawData
        section_data = section.get_data(section_va, section_size)

        if section_name == ".text":
            # Extract long strings
            yield from chain(
                extract_build_id(section_data, min_length),
                extract_stackstring(extract_stackstring_pattern, section_data, min_length),
            )

            if arch == "amd64":
                yield from chain(
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring64, arch, regex_offset=7
                    ),
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring64_2, arch, regex_offset=13
                    ),
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring64_3, arch, regex_offset=15
                    ),
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring64_4, arch, regex_offset=20
                    ),
                )

            else:
                yield from chain(
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring32, arch
                    ),
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring32_2, arch
                    ),
                    extract_strings_referenced_by_code(
                        pe, section_data, section_va, min_length, extract_longstring32_3, arch
                    ),
                )

        if section_name == ".rdata":
            yield from chain(
                extract_reflection_strings(pe, section_data, section_va, min_length),
                extract_string_blob2(pe, section_data, section_va, min_length),
                extract_file_path_strings(pe, section_data, section_va, min_length),
            )

        if section_name in (".rdata", ".data"):
            # Extract string blob in .rdata and .data section
            yield from extract_strings_referenced_by_string_table(pe, section_data, min_length, arch)

    try:
        yield from extract_strings_from_import_data(pe)
    except ValueError:
        pass


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
        addr = strings_obj.offset
        string = strings_obj.string
        print(string, hex(addr))


if __name__ == "__main__":
    sys.exit(main())
