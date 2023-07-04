# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import struct
import logging
import argparse
from typing import List, Tuple, Iterable, Optional
from pathlib import Path
from itertools import chain

import pefile
from floss.main import get_static_strings
from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 6


def extract_stackstrings(extract_stackstring_pattern, section_data, offset, min_length) -> List[StaticString]:
    stack_strings = list()
    for m in extract_stackstring_pattern.finditer(section_data):
        for i in range(1, 8):
            try:
                binary_string = m.group(i)
                if not binary_string:
                    continue

                # need to subtract opcode bytes offset
                off_regex = len(m.group(0)) - len(binary_string)
                addr = offset + off_regex + m.start()
                try:
                    string = StaticString.from_utf8(binary_string, addr, min_length)
                    stack_strings.append(string)
                except ValueError:
                    pass
            except AttributeError:
                break

    return stack_strings


def xrefs_in_text_segment(
    pe: pefile.PE, text_segment_data, text_segment_va, rdata_start_va, rdata_end_va, arch
) -> List[int]:
    """
    Find cross-references to a string in the .text segment.

    This function aims to locate cross-references to a string
    from the .text segment to the .rdata segment of the binary.
    Cross-references are representations of instructions that
    reference the string data. The function searches for these c
    ross-references and retrieves their addresses.

    Cross-references are of the form:

    AMD64:
    .text:0000000000408389 48 8D 05 80 08 0C 00            lea     rax, unk_4C8C10
    .text:00000000004736F0 4C 8D 05 84 47 03 00            lea     r8, unk_4A7E7B

    386:
    .text:004806D2 8D 05 EC 1D 4A 00                       lea     eax, unk_4A1DEC


    """
    text_segment_xrefs = list()

    if arch == "amd64":
        text_regex = re.compile(b"(\x48|\x4C)\x8D(?=.(?P<offset>....))", re.DOTALL)
        for match in text_regex.finditer(text_segment_data):
            offset = struct.unpack("<I", match.group("offset"))[0]
            address = text_segment_va + match.start() + offset + 7 + pe.OPTIONAL_HEADER.ImageBase
            if rdata_start_va <= address <= rdata_end_va:
                text_segment_xrefs.append(address)
    else:
        text_regex = re.compile(b"\x8D(?=.(?P<offset>....))", re.DOTALL)
        for match in text_regex.finditer(text_segment_data):
            offset = struct.unpack("<I", match.group("offset"))[0]
            address = offset
            if rdata_start_va <= address <= rdata_end_va:
                text_segment_xrefs.append(address)

    return text_segment_xrefs


def xrefs_in_rdata_data_segment(section_data, rdata_start_va, rdata_end_va, arch) -> List[int]:
    """
    Find cross-references to a string in the .rdata segment.
    All cross-references are of the form:
    00000000004C9D00  19 8C 4A 00 00 00 00 00  0A 00 00 00 00 00 00 00  ..J.............
    """

    if arch == "amd64":
        size = 0x10
        fmt = "<QQ"
    else:
        size = 0x8
        fmt = "<II"

    xrefs_in_rdata_data_segment = list()

    for addr in range(0, len(section_data) - size // 2, size // 2):
        curr = section_data[addr : addr + size]
        s_off, s_size = struct.unpack_from(fmt, curr)

        if not (1 <= s_size < 128):
            continue

        if rdata_start_va <= s_off <= rdata_end_va:
            xrefs_in_rdata_data_segment.append(s_off)

    return xrefs_in_rdata_data_segment


def xrefs_in_rdata_data_segment_get_approximate_location(pe, section_data, rdata_start_va, rdata_end_va, arch):
    """
    Find cross-references to a string in the .rdata segment.
    All cross-references are of the form:
    00000000004C9D00  19 8C 4A 00 00 00 00 00  0A 00 00 00 00 00 00 00  ..J.............
    """

    if arch == "amd64":
        size = 0x10
        fmt = "<QQ"
    else:
        size = 0x8
        fmt = "<II"

    xrefs_in_rdata_data_segment = list()

    for addr in range(0, len(section_data) - size // 2, size // 2):
        curr = section_data[addr : addr + size]
        s_off, s_size = struct.unpack_from(fmt, curr)

        if not (1 <= s_size < 128):
            continue

        s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase

        if not pe.get_section_by_rva(s_rva):
            continue

        try:
            string = pe.get_string_at_rva(s_rva, s_size).decode("utf-8")
        except UnicodeDecodeError:
            continue

        if string.isprintable() is False or string == "":
            continue

        if rdata_start_va <= s_off <= rdata_end_va:
            xrefs_in_rdata_data_segment.append((s_off, s_off + s_size))

    return xrefs_in_rdata_data_segment


def find_longest_range(sub_ranges):
    """
    Find the longest range in a list of ranges.
    Example:
    [(3, 6), (188, 204), (10, 12), (40, 200), (7, 9), (1, 2), (4, 8), (13, 16), (90, 100)] -> [(1, 16), (40, 204)]
    """
    ranges = sorted(sub_ranges)
    longest_range = [ranges[0]]

    for i in range(1, len(ranges)):
        current_range = ranges[i]
        prev_range = longest_range[-1]

        if current_range[0] <= prev_range[1] + 1:
            longest_range[-1] = (prev_range[0], max(prev_range[1], current_range[1]))
        else:
            longest_range.append(current_range)

    longest_range = sorted(longest_range, key=lambda x: x[1] - x[0], reverse=True)

    return longest_range[0]


def expand_range(rdata_segment_data, range_min, range_max, rdata_start_va, rdata_end_va):
    """
    Expand a range to include all printable characters.
    i.e. search if there are any 2 null bytes before and after the range.
    """

    extended_range_min = range_min

    for i in range(range_min, rdata_start_va, -1):
        j = i - rdata_start_va
        if rdata_segment_data[j] == 0 and rdata_segment_data[j + 1] == 0:
            extended_range_min = j + 2
            break

    extended_range_max = range_max
    for i in range(range_max, rdata_end_va):
        j = i - rdata_start_va
        if rdata_segment_data[j] == 0 and rdata_segment_data[j + 1] == 0:
            extended_range_max = j
            break

    return (extended_range_min, extended_range_max)


def split_string_by_indices(string, indices, max_xref_string_start, max_xref_string_end):
    """Split a string into parts by indices."""
    parts = []
    previous_index = 0

    for index in indices:
        index -= max_xref_string_start
        if index > max_xref_string_end:
            break
        if index < 0:
            continue
        parts.append((index, string[previous_index:index]))
        previous_index = index

    parts.append((previous_index, string[previous_index:]))

    return parts


def count_elements_between(numbers, start_number, end_number) -> int:
    """
    Count the number of elements between two numbers in a sorted list.
    Example:
        numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        start_number = 3
        end_number = 7
        count = 5
        i.e [3, 4, 5, 6, 7]
    """
    start_index = 0
    end_index = len(numbers) - 1

    while start_index <= end_index:
        mid_index = (start_index + end_index) // 2
        if numbers[mid_index] < start_number:
            start_index = mid_index + 1
        else:
            end_index = mid_index - 1

    while end_index < len(numbers) - 1 and numbers[end_index + 1] <= end_number:
        end_index += 1

    count = end_index - start_index + 1
    return count


def extract_go_strings(sample: Path, min_length=MIN_STR_LEN) -> List[StaticString]:
    """Extract strings from Go binaries.

    Args:
        path (Path): Path to the binary.
        min_length (int): Minimum length of the string.

    Returns:
        list: List of strings.

    Reference: https://github.com/mandiant/flare-floss/issues/779
    """

    try:
        pe = pefile.PE(sample)
    except pefile.PEFormatError as err:
        logger.debug(f"invalid PE file: {err}")
        return []

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
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

        # TODO
        """
        .text:000000000042E596 48 89 44 24 28                mov     [rsp+158h+var_130], rax
        .text:000000000042E59B 48 BA 74 69 6D 65 42 65 67 69 mov     rdx, 'igeBemit'
        .text:000000000042E5A5 48 89 94 24 9D 00 00 00       mov     [rsp+158h+var_BB], rdx
        .text:000000000042E5AD 48 BA 6E 50 65 72 69 6F 64 00 mov     rdx, 'doirePn'
        """

        # The "?=" in the regular expression is a lookahead assertion that allows us to match a specific pattern without including it in the actual match.
        # The "re.DOTALL" flag ensures that the dot "." in the regular expression matches any character, including newline characters.

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
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
            text_segment_data = section_data
            text_segment_va = section_va
            text_segment_raw = section.PointerToRawData

        elif section_name == ".rdata":
            rdata_segment_data = section_data
            rdata_segment_va = section_va
            rdata_segment_pointer_to_raw_data = section.PointerToRawData

        elif section_name == ".data":
            data_segment_data = section_data

    rdata_start_va = rdata_segment_va + pe.OPTIONAL_HEADER.ImageBase
    rdata_end_va = rdata_start_va + len(rdata_segment_data)

    # Find XREFs to longest string
    # XREFs from ->
    # 1. text segment
    # 2. rdata segment
    # 3. data segment

    sub_ranges = xrefs_in_rdata_data_segment_get_approximate_location(
        pe, rdata_segment_data, rdata_start_va, rdata_end_va, arch
    )

    (range_min, range_max) = find_longest_range(sub_ranges)

    # Now we have the range of the longest string, expand from this range till we find \x00 at both ends
    extended_range = expand_range(rdata_segment_data, range_min, range_max, rdata_start_va, rdata_end_va)

    xrefs = (
        xrefs_in_text_segment(pe, text_segment_data, text_segment_va, rdata_start_va, rdata_end_va, arch)
        + xrefs_in_rdata_data_segment(rdata_segment_data, rdata_start_va, rdata_end_va, arch)
        + xrefs_in_rdata_data_segment(data_segment_data, rdata_start_va, rdata_end_va, arch)
    )

    # get unique xrefs
    xrefs = list(set(xrefs))
    xrefs.sort()

    # Split the longest_string into substrings by the xrefs
    indices = list()
    for xref in xrefs:
        index = xref - rdata_start_va
        indices.append(index)

    max_xref_string = rdata_segment_data[extended_range[0] : extended_range[1]]
    max_xref_string_start = extended_range[0]
    max_xref_string_end = extended_range[1]

    # Split the longest string into substrings by the xrefs
    parts = split_string_by_indices(max_xref_string, indices, max_xref_string_start, max_xref_string_end)

    utf_8_parts = list()

    for part in parts:
        try:
            addr = max_xref_string_start + part[0] + rdata_segment_pointer_to_raw_data - len(part[1])
            utf_8_parts.append(StaticString.from_utf8(part[1], addr, min_length))
        except ValueError:
            continue

    stack_strings = extract_stackstrings(extract_stackstring_pattern, text_segment_data, text_segment_raw, min_length)
    static_strings = get_static_strings(Path(sample), min_length)

    return utf_8_parts + stack_strings  # TODO + static_strings


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
