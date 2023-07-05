# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import struct
import logging
import pathlib
import argparse
import collections
from typing import Dict, List, Tuple, Iterable, Optional, TypeAlias
from pathlib import Path
from itertools import chain
from dataclasses import dataclass

import pefile

from floss.main import get_static_strings
from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 6


def extract_stackstrings(extract_stackstring_pattern, section_data, min_length) -> List[StaticString]:
    stack_strings = list()
    for m in extract_stackstring_pattern.finditer(section_data):
        for i in range(1, 8):
            try:
                binary_string = m.group(i)
                if not binary_string:
                    continue

                addr = m.start()
                try:
                    string = StaticString.from_utf8(binary_string, addr, min_length)
                    stack_strings.append(string)
                except ValueError:
                    pass
            except AttributeError:
                break

    return stack_strings


VA: TypeAlias = int


def get_amd64_lea_xrefs(buf: bytes, base_addr: VA) -> Iterable[VA]:
    rip_relative_insn_length = 7
    rip_relative_insn_re = re.compile(
        # use rb, or else double escape the term "\x0D", or else beware!
        rb"""
        (?:                   # non-capturing group
              \x48 \x8D \x05  # 48 8d 05 aa aa 00 00    lea    rax,[rip+0xaaaa] 
            | \x48 \x8D \x0D  # 48 8d 0d aa aa 00 00    lea    rcx,[rip+0xaaaa]
            | \x48 \x8D \x15  # 48 8d 15 aa aa 00 00    lea    rdx,[rip+0xaaaa]
            | \x48 \x8D \x1D  # 48 8d 1d aa aa 00 00    lea    rbx,[rip+0xaaaa]
            | \x48 \x8D \x2D  # 48 8d 2d aa aa 00 00    lea    rbp,[rip+0xaaaa]
            | \x48 \x8D \x35  # 48 8d 35 aa aa 00 00    lea    rsi,[rip+0xaaaa]
            | \x48 \x8D \x3D  # 48 8d 3d aa aa 00 00    lea    rdi,[rip+0xaaaa]
            | \x4C \x8D \x05  # 4c 8d 05 aa aa 00 00    lea     r8,[rip+0xaaaa]
            | \x4C \x8D \x0D  # 4c 8d 0d aa aa 00 00    lea     r9,[rip+0xaaaa]
            | \x4C \x8D \x15  # 4c 8d 15 aa aa 00 00    lea    r10,[rip+0xaaaa]
            | \x4C \x8D \x1D  # 4c 8d 1d aa aa 00 00    lea    r11,[rip+0xaaaa]
            | \x4C \x8D \x25  # 4c 8d 25 aa aa 00 00    lea    r12,[rip+0xaaaa]
            | \x4C \x8D \x2D  # 4c 8d 2d aa aa 00 00    lea    r13,[rip+0xaaaa]
            | \x4C \x8D \x35  # 4c 8d 35 aa aa 00 00    lea    r14,[rip+0xaaaa]
            | \x4C \x8D \x3D  # 4c 8d 3d aa aa 00 00    lea    r15,[rip+0xaaaa]
        )
        (?P<offset>....)
        """,
        re.DOTALL | re.VERBOSE,
    )

    for match in rip_relative_insn_re.finditer(buf):
        offset_bytes = match.group("offset")
        offset = struct.unpack("<i", offset_bytes)[0]

        yield base_addr + match.start() + offset + rip_relative_insn_length


def get_i386_lea_xrefs(buf: bytes) -> Iterable[VA]:
    absolute_insn_re = re.compile(
        rb"""
        (
              \x8D \x05  # 8d 05 aa aa 00 00       lea    eax,ds:0xaaaa
            | \x8D \x1D  # 8d 1d aa aa 00 00       lea    ebx,ds:0xaaaa
            | \x8D \x0D  # 8d 0d aa aa 00 00       lea    ecx,ds:0xaaaa
            | \x8D \x15  # 8d 15 aa aa 00 00       lea    edx,ds:0xaaaa
            | \x8D \x35  # 8d 35 aa aa 00 00       lea    esi,ds:0xaaaa
            | \x8D \x3D  # 8d 3d aa aa 00 00       lea    edi,ds:0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in absolute_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<I", address_bytes)[0]

        yield address


def get_image_range(pe: pefile.PE) -> Tuple[VA, VA]:
    """Return the range of the image in memory."""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    return image_base, image_base + image_size


def get_lea_xrefs(pe: pefile.PE) -> Iterable[VA]:
    low, high = get_image_range(pe)

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue

        code = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            xrefs = get_amd64_lea_xrefs(code, section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            xrefs = get_i386_lea_xrefs(code)
        else:
            raise ValueError("unhandled architecture")

        for xref in xrefs:
            if low <= xref < high:
                yield xref


@dataclass
class StructString:
    address: VA
    length: int


def get_amd64_struct_string_candidates(buf: bytes) -> Iterable[StructString]:
    for offset in range(0, len(buf) - 0x8, 0x8):
        address, length = struct.unpack_from("<QQ", buf, offset)
        yield StructString(address, length)


def get_i386_struct_string_candidates(buf: bytes) -> Iterable[StructString]:
    for offset in range(0, len(buf) - 0x4, 0x4):
        address, length = struct.unpack_from("<II", buf, offset)
        yield StructString(address, length)


def get_struct_string_instances(pe: pefile.PE) -> Iterable[StructString]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    low, high = get_image_range(pe)

    for section in pe.sections:
        if section.IMAGE_SCN_MEM_EXECUTE:
            continue

        if not section.IMAGE_SCN_MEM_READ:
            continue

        data = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            candidates = get_amd64_struct_string_candidates(data)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            candidates = get_i386_struct_string_candidates(data)
        else:
            raise ValueError("unhandled architecture")

        for candidate in candidates:
            va = candidate.address
            rva = va - image_base

            if not (low <= va < high):
                continue

            target_section = pe.get_section_by_rva(rva)
            if not target_section:
                # string instance must be in a section
                continue

            if target_section.IMAGE_SCN_MEM_EXECUTE:
                # string instances aren't found with the code
                continue

            if not target_section.IMAGE_SCN_MEM_READ:
                # string instances must be readable, naturally
                continue

            try:
                sbuf = pe.get_data(rva, candidate.length)
            except pefile.PEFormatError:
                # failed to read data at RVA
                continue

            if len(sbuf) != candidate.length:
                # we must be able to read the entire string data
                # or it is not a valid Go string
                continue

            try:
                s = sbuf.decode("utf-8")
            except UnicodeDecodeError:
                continue

            if not s:
                continue

            if s.encode("utf-8") != sbuf:
                # re-encoding the string should produce the same bytes,
                # otherwise, the string may not be the length intended.
                continue

            yield candidate


def get_string_blob_range(pe: pefile.PE, struct_strings: List[StructString]) -> Tuple[VA, VA]:
    """
    find the most common range of bytes between | 00 00 | pairs
    that contains the data from a likely struct string.

    we don't expect UTF-8 data to ever contain | 00 00 |, so this
    shouldn't be found in the string blob.

    we assume that the range with the most pointers like this is
    the string blob. this might not be the case if:
      - there's more than one string blob
      - there's lots of structures that look like struct String but aren't
      - ???

    these don't seem likely today, but possible.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # cache the section data so that we can avoid pefile overhead
    section_datas: List[Tuple[VA, VA, bytes]] = []
    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_READ:
            continue

        section_datas.append(
            (
                image_base + section.VirtualAddress,
                image_base + section.VirtualAddress + section.SizeOfRawData,
                section.get_data(),
            )
        )

    range_votes = collections.Counter()
    for instance in struct_strings:
        section_start, _, section_data = next(filter(lambda s: s[0] <= instance.address < s[1], section_datas))

        instance_offset = instance.address - section_start

        next_null = section_data.find(b"\x00\x00", instance_offset)
        if next_null == -1:
            continue

        prev_null = section_data.rfind(b"\x00\x00", 0, instance_offset)
        if prev_null == -1:
            continue

        range_votes[(section_start + prev_null, section_start + next_null)] += 1

    for (prev_null, next_null), count in range_votes.most_common():
        if count == 1:
            continue

        logger.debug("range vote: 0x%x 0x%x 0x%x", prev_null + section_start, next_null + section_start, count)

    most_common, count = range_votes.most_common(1)[0]
    return most_common


def get_string_blob_strings(pe: pefile.PE) -> Iterable[Tuple[VA, str]]:
    image_base = pe.OPTIONAL_HEADER.ImageBase

    struct_strings = list(get_struct_string_instances(pe))

    string_blob_range = get_string_blob_range(pe, struct_strings)
    string_blob_start, string_blob_end = string_blob_range
    string_blob_size = string_blob_end - string_blob_start
    string_blob_buf = pe.get_data(string_blob_range[0] - image_base, string_blob_size)

    string_blob_pointers: List[VA] = []

    for instance in struct_strings:
        if not (string_blob_range[0] <= instance.address < string_blob_range[1]):
            continue

        string_blob_pointers.append(instance.address)

    for xref in get_lea_xrefs(pe):
        if not (string_blob_range[0] <= xref < string_blob_range[1]):
            continue

        string_blob_pointers.append(xref)

    last_size = 0
    string_blob_pointers = list(sorted(set(string_blob_pointers)))
    for start, end in zip(string_blob_pointers, string_blob_pointers[1:]):
        size = end - start

        if not (string_blob_start <= start < string_blob_end):
            continue

        if not (string_blob_start <= end < string_blob_end):
            continue

        string_blob_offset = start - string_blob_start
        sbuf = string_blob_buf[string_blob_offset : string_blob_offset + size]

        try:
            s = sbuf.decode("utf-8")
        except UnicodeDecodeError:
            continue

        if not s:
            continue

        if last_size > len(s):
            # today, the string blob is stored in order of length,
            # small to large,
            # so we can detect when we missed a string,
            # for example:
            #
            #   0x4aab99:  nmidlelocked=
            #   0x4aaba7:  on zero Value
            #   0x4aabb5:  out of range  procedure in        <<< missed!
            #   0x4aabd1:  to finalizer
            #   0x4aabdf:  untyped args
            #   0x4aabed: -thread limit
            #
            # we probably missed the string: " procedure in "
            logger.warn("probably missed a string blob string ending at: 0x%x", start - 1)

        yield start, s

    # when we recover the last string from the string blob table,
    # it may have some junk at the end.
    #
    # this is because the string blob might be stored next to non-zero, non-string data.
    # when we search for the | 00 00 | for the end of the string blob,
    # we may pick up some of this non-string data.
    #
    # so we try to recover the last string by searching for the longest
    # valid UTF-8 string from that last pointer.
    # it still may have junk appended to it, but at least its UTF-8.
    last_pointer = string_blob_pointers[-1]
    last_pointer_offset = last_pointer - string_blob_start
    last_buf = string_blob_buf[last_pointer_offset:]
    for size in range(len(last_buf), 0, -1):
        try:
            s = last_buf[:size].decode("utf-8")
        except UnicodeDecodeError:
            continue
        else:
            yield last_pointer, s
            break


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

    # find strings that has maximum xrefs
    non_printable_pattern = b"[\x00-\x1F\x7F-\xFF]{2}(?P<blob>)*[^\x00-\x1F\x7F-\xFF]{2}[\x00-\x1F\x7F-\xFF]{2}"
    previous_index = 0

    split_parts = []

    for match in re.finditer(non_printable_pattern, rdata_segment_data):
        string = rdata_segment_data[previous_index : match.start()]
        split_parts.append((string, previous_index, match.start()))
        previous_index = match.end()

    number_of_references = 0
    maximum_references = 0

    max_xref_string = 0

    for part in split_parts:
        number_of_references = count_elements_between(indices, part[1], part[2])

        if number_of_references > maximum_references:
            maximum_references = number_of_references
            max_xref_string = part[0]
            max_xref_string_start = part[1]
            max_xref_string_end = part[2]

    parts = split_string_by_indices(max_xref_string, indices, max_xref_string_start, max_xref_string_end)

    utf_8_parts = list()

    for part in parts:
        try:
            addr = max_xref_string_start + part[0] + rdata_segment_pointer_to_raw_data - len(part[1])
            utf_8_parts.append(StaticString.from_utf8(part[1], addr, min_length))
        except ValueError:
            continue

    stack_strings = extract_stackstrings(extract_stackstring_pattern, text_segment_data, min_length)
    static_strings = get_static_strings(Path(sample), min_length)

    return utf_8_parts + stack_strings + static_strings


def amain(argv=None):
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

    logging.basicConfig(level=logging.DEBUG)

    p = pathlib.Path(args.path)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    for va, s in get_string_blob_strings(pe):
        print(f"{va:#x}: {s}")


if __name__ == "__main__":
    sys.exit(main())
