#!/usr/bin/env python
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import os
import sys
import mmap
import codecs
import string
import logging
import argparse
import textwrap
import contextlib
from enum import Enum
from time import time
from typing import Set, List, Tuple, Optional

import tabulate
import viv_utils

import floss.logging
import floss.strings as strings
import floss.version
import floss.render.json
import floss.stackstrings as stackstrings
import floss.string_decoder as string_decoder
from floss.const import MAX_FILE_SIZE, DEFAULT_MIN_LENGTH, SUPPORTED_FILE_MAGIC
from floss.utils import hex, get_vivisect_meta_info
from floss.results import Metadata, AddressType, StackString, DecodedString, ResultDocument, StringEncoding
from floss.version import __version__
from floss.identify import find_decoding_functions

logger = floss.logging.getLogger("floss")


class LoadNotSupportedError(Exception):
    pass


class WorkspaceLoadError(ValueError):
    pass


def decode_strings(
    vw, functions: List[int], min_length: int, no_filter=False, max_instruction_count=20000, max_hits=1
) -> List[DecodedString]:
    """
    FLOSS string decoding algorithm

    arguments:
        vw: the workspace
        functions: addresses of the candidate decoding routines
        min_length: minimun string length
        max_instruction_count: max number of instructions to emulate per function
        max_hits: max number of emulations per instruction
    """
    decoded_strings = []
    function_index = viv_utils.InstructionFunctionIndex(vw)
    for fva in functions:
        for ctx in string_decoder.extract_decoding_contexts(vw, fva, max_hits):
            for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx, max_instruction_count):
                for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                    for decoded_string in string_decoder.extract_strings(delta_bytes, min_length, no_filter):
                        decoded_strings.append(decoded_string)
    return decoded_strings


def sanitize_string_for_printing(s: str) -> str:
    """
    Return sanitized string for printing.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = s.replace("\\\\", "\\")  # print single backslashes
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string


def sanitize_string_for_script(s: str) -> str:
    """
    Return sanitized string that is added to IDAPython script content.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = sanitize_string_for_printing(s)
    sanitized_string = sanitized_string.replace("\\", "\\\\")
    sanitized_string = sanitized_string.replace('"', '\\"')
    return sanitized_string


DEFAULT_MAX_INSN_COUNT = 20000
DEFAULT_MAX_ADDRESS_REVISITS = 0


class ArgumentValueError(ValueError):
    pass


class ArgumentParser(argparse.ArgumentParser):
    """
    argparse will call sys.exit upon parsing invalid arguments.
    we don't want that, because we might be parsing args within test cases, etc.
    so, we override the behavior to raise a ArgumentValueError instead.

    note: the help message will still be printed to the console.

    this strategy is originally described here: https://stackoverflow.com/a/16942165/87207
    """

    def error(self, message):
        self.print_help(sys.stderr)
        raise ArgumentValueError("%s: error: %s\n" % (self.prog, message))


def make_parser(argv):
    desc = "The FLARE team's open-source tool to extract obfuscated strings from malware.\n  %(prog)s {:s} - https://github.com/fireeye/flare-floss/".format(
        __version__
    )
    epilog = textwrap.dedent(
        """
        only displaying core arguments, run `floss --help -x` to see all supported arguments

        examples:
          extract all strings from an executable
            floss suspicious.exe

          extract all strings from shellcode
            floss -s shellcode.bin
        """
    )
    epilog_expert = textwrap.dedent(
        """
        examples:
          only show strings of minimun length 6
            floss -n 6 suspicious.exe

          only show stack strings
            floss --no-static-strings --no-decoded-strings suspicious.exe
        """
    )

    expert = "-x" in argv

    parser = ArgumentParser(
        description=desc,
        epilog=epilog_expert if expert else epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-x", action="store_true", dest="x", help="enable eXpert arguments, see `floss --help -x`")
    parser.add_argument(
        "--version", action="version", version="%(prog)s {:s}".format(__version__), help=argparse.SUPPRESS
    )

    parser.add_argument(
        "sample",
        type=str,
        help="path to sample to analyze",
    )

    output_group = parser.add_argument_group("rendering arguments")
    output_group.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    output_group.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose result document (no effect with --json)"
    )
    output_group.add_argument(
        "-vv", "--vverbose", action="store_true", help="enable very verbose result document (no effect with --json)"
    )
    output_group.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )

    logging_group = parser.add_argument_group("logging arguments")

    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    analysis_group = parser.add_argument_group("analysis arguments")
    analysis_group.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        default=DEFAULT_MIN_LENGTH,
        help="minimum string length" if expert else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--functions",
        type=lambda x: int(x, 0x10),
        nargs="+",
        help="only analyze the specified functions, hex-encoded like 0x401000, space-separate multiple functions"
        if expert
        else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--no-filter",
        action="store_true",
        help="do not filter deobfuscated strings (may result in many false positive strings)"
        if expert
        else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--max-instruction-count",
        type=int,
        default=DEFAULT_MAX_INSN_COUNT,
        help="maximum number of instructions to emulate per function" if expert else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--max-address-revisits",
        dest="max_address_revisits",
        type=int,
        default=DEFAULT_MAX_ADDRESS_REVISITS,
        help="maximum number of address revisits per function" if expert else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--no-static-strings",
        dest="no_static_strings",
        action="store_true",
        help="do not show static ASCII and UTF-16 strings" if expert else argparse.SUPPRESS,
    )
    analysis_group.add_argument(
        "--no-decoded-strings",
        dest="no_decoded_strings",
        action="store_true",
        help="do not show decoded strings" if expert else argparse.SUPPRESS,
    )
    analysis_group.add_argument(
        "--no-stack-strings",
        dest="no_stack_strings",
        action="store_true",
        help="do not show stackstrings" if expert else argparse.SUPPRESS,
    )

    shellcode_group = parser.add_argument_group(
        "shellcode arguments",
    )
    shellcode_group.add_argument(
        "-s",
        "--shellcode",
        dest="is_shellcode",
        action="store_true",
        help="analyze shellcode",
    )
    shellcode_group.add_argument(
        "--shellcode-entry-point",
        default=0,
        type=lambda x: int(x, 0x10),
        help="shellcode entry point, hex-encoded like 0x401000" if expert else argparse.SUPPRESS,
    )
    shellcode_group.add_argument(
        "--shellcode-base",
        default=0x1000,
        type=lambda x: int(x, 0x10),
        help="shellcode base offset, hex-encoded like 0x401000" if expert else argparse.SUPPRESS,
    )
    shellcode_group.add_argument(
        "--shellcode-arch",
        default=None,
        type=str,
        choices=[e.value for e in Architecture],
        help="shellcode architecture, default: autodetect" if expert else argparse.SUPPRESS,
    )

    return parser


def set_log_config(args):
    if args.quiet:
        log_level = logging.WARNING
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    # install the log message colorizer to the default handler.
    # because basicConfig is just above this,
    # handlers[0] is a StreamHandler to STDERR.
    #
    # calling this code from outside script main may do something unexpected.
    logging.getLogger().handlers[0].setFormatter(floss.logging.ColorFormatter())


def validate_sample_path(parser, args) -> str:
    """
    Return validated input file path or terminate program.
    """
    try_help_msg = "Try 'floss -h' for more information"

    if not os.path.exists(args.sample):
        parser.error("File '%s' does not exist\n%s" % (args.sample, try_help_msg))

    if not os.path.isfile(args.sample):
        parser.error("'%s' is not a file\n%s" % (args.sample, try_help_msg))

    return args.sample


def select_functions(vw, asked_functions: Optional[List[int]]) -> Set[int]:
    """
    Given a workspace and an optional list of function addresses,
    collect the set of valid functions,
    or all valid function addresses.

    arguments:
      asked_functions: the functions a user wants, or None.

    raises:
      ValueError: if an asked for function does not exist in the workspace.
    """
    functions = set(vw.getFunctions())
    if not asked_functions:
        # user didn't specify anything, so return them all.
        return functions

    asked_functions_ = set(asked_functions or [])

    # validate that all functions requested by the user exist.
    missing_functions = sorted(asked_functions_ - functions)
    if missing_functions:
        raise ValueError("failed to find functions: %s" % (", ".join(map(hex, sorted(missing_functions)))))

    return asked_functions_


def filter_unique_decoded(decoded_strings):
    unique_values = set()
    originals = []
    for decoded in decoded_strings:
        hashable = (decoded.string, decoded.decoded_at, decoded.decoding_routine)
        if hashable not in unique_values:
            unique_values.add(hashable)
            originals.append(decoded)
    return originals


def is_workspace_file(sample_file_path):
    """
    Return if input file is a vivisect workspace, based on file extension
    :param sample_file_path:
    :return: True if file extension is .viv, False otherwise
    """
    if os.path.splitext(sample_file_path)[1] == ".viv":
        return True
    return False


def is_supported_file_type(sample_file_path):
    """
    Return if FLOSS supports the input file type, based on header bytes
    :param sample_file_path:
    :return: True if file type is supported, False otherwise
    """
    with open(sample_file_path, "rb") as f:
        magic = f.read(2)

    if magic in SUPPORTED_FILE_MAGIC:
        return True
    else:
        return False


def print_decoding_results(decoded_strings: List[DecodedString], quiet=False):
    """
    Print results of string decoding phase.

    :param decoded_strings: list of decoded strings ([DecodedString])
    :param quiet: print strings only, suppresses headers
    """
    logger.info("decoded %d strings" % len(decoded_strings))
    fvas = set([i.decoding_routine for i in decoded_strings])
    for fva in fvas:
        grouped_strings = [ds for ds in decoded_strings if ds.decoding_routine == fva]
        len_ds = len(grouped_strings)
        if len_ds > 0:
            logger.info("using decoding function at 0x%X (decoded %d strings):" % (fva, len_ds))
            print_decoded_strings(grouped_strings, quiet=quiet)


def print_decoded_strings(decoded_strings: List[DecodedString], quiet=False):
    """
    Print decoded strings.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param quiet: print strings only, suppresses headers
    """
    if quiet:
        for ds in decoded_strings:
            print(sanitize_string_for_printing(ds.string))
    else:
        ss = []
        for ds in decoded_strings:
            s = sanitize_string_for_printing(ds.string)
            if ds.address_type == AddressType.STACK:
                offset_string = "[STACK]"
            elif ds.address_type == AddressType.HEAP:
                offset_string = "[HEAP]"
            else:
                offset_string = hex(ds.address or 0)
            ss.append((offset_string, hex(ds.decoded_at), s))

        if len(ss) > 0:
            print(tabulate.tabulate(ss, headers=["Offset", "Called At", "String"]))


def get_file_as_mmap(path):
    """
    Returns an mmap object of the file
    :param path: path of the file to map
    """
    with open(path, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)


# TODO: move to floss.render
def print_static_strings(results: ResultDocument):
    """
    Print static ASCII and UTF-16 strings from provided file.
    """
    ascii_strings = [s.string for s in results.strings.static_strings if s.encoding == StringEncoding.ASCII]
    unicode_strings = [s.string for s in results.strings.static_strings if s.encoding == StringEncoding.UTF16LE]

    if not ascii_strings:
        print("static ASCII strings (%d): none" % (len(unicode_strings)))
    else:
        print("static ASCII strings (%d):" % (len(ascii_strings)))
        for s in ascii_strings:
            print(s)
        print()

    if not unicode_strings:
        print("static UTF-16LE strings (%d): none" % (len(unicode_strings)))
    else:
        print("static UTF-16LE strings (%d):" % (len(unicode_strings)))
        for s in unicode_strings:
            print(s)


def print_stack_strings(extracted_strings: List[StackString], quiet=False):
    """
    Print extracted stackstrings.
    :param extracted_strings: list of stack strings ([StackString])
    :param quiet: print strings only, suppresses headers
    """
    count = len(extracted_strings)

    logger.info("FLOSS extracted %d stackstrings" % (count))

    if quiet:
        for ss in extracted_strings:
            print("%s" % (ss.string))
    elif count > 0:
        print(
            tabulate.tabulate(
                [(hex(s.function), hex(s.frame_offset), s.string) for s in extracted_strings],
                headers=["Function", "Frame Offset", "String"],
            )
        )


def print_file_meta_info(vw, selected_functions: Set[int]):
    logger.info("analysis summary:")
    for k, v in get_vivisect_meta_info(vw, selected_functions).items():
        logger.info("  %s: %s" % (k, v or "N/A"))


def load_workspace(sample_file_path):
    # inform user that getWorkspace implicitly loads saved workspace if .viv file exists
    if is_workspace_file(sample_file_path) or os.path.exists("%s.viv" % sample_file_path):
        logger.info("loading existing vivisect workspace...")
    else:
        if not is_supported_file_type(sample_file_path):
            raise LoadNotSupportedError(
                "FLOSS currently supports the following formats for string decoding and "
                "stackstrings: PE\nYou can analyze shellcode using the -s switch. See the "
                "help (-h) for more information."
            )
        logger.info("Generating vivisect workspace...")
    return viv_utils.getWorkspace(sample_file_path, should_save=False)


class Architecture(str, Enum):
    i386 = "i386"
    amd64 = "amd64"


def load_shellcode_workspace(
    sample_file_path: str, shellcode_entry_point: int, shellcode_base: int, arch: Optional[Architecture] = None
):
    if is_supported_file_type(sample_file_path):
        logger.warning("analyzing supported file type as shellcode - this will likely yield weaker analysis.")

    with open(sample_file_path, "rb") as f:
        shellcode_data = f.read()

    if not arch:
        # choose arch with most functions, idea by Jay G.
        candidates: List[Tuple[int, Architecture]] = []
        for candidate in Architecture:
            vw = viv_utils.getShellcodeWorkspace(
                shellcode_data, candidate, base=shellcode_base, analyze=False, should_save=False
            )
            function_count = vw.getFunctions()
            if function_count == 0:
                continue

            candidates.append((function_count, candidate))

        if not candidates:
            raise ValueError("could not generate vivisect workspace")

        # pick the arch with the largest function count
        (_, arch) = sorted(candidates, reverse=True)[0]

        logger.info("detected shellcode arch: %s", arch)

    logger.info(
        "generating vivisect workspace for shellcode, arch: %s, base: 0x%x, entry point: 0x%x...",
        arch,
        shellcode_base,
        shellcode_entry_point,
    )

    vw = viv_utils.getShellcodeWorkspace(
        shellcode_data,
        arch=arch,
        base=shellcode_base,
        entry_point=shellcode_entry_point,
        should_save=False,
    )

    vw.setMeta("StorageName", "%s.viv" % sample_file_path)

    return vw


def load_vw(
    sample_file_path: str,
    is_shellcode: bool,
    shellcode_entry_point: Optional[int],
    shellcode_base: Optional[int],
    shellcode_arch: Optional[Architecture],
):
    try:
        if is_shellcode:
            assert shellcode_entry_point is not None
            assert shellcode_base is not None
            return load_shellcode_workspace(sample_file_path, shellcode_entry_point, shellcode_base, shellcode_arch)
        else:
            return load_workspace(sample_file_path)
    except LoadNotSupportedError as e:
        raise WorkspaceLoadError(str(e))
    except Exception as e:
        logger.debug("vivisect error: %s", e, exc_info=True)
        raise WorkspaceLoadError(str(e))


def main(argv=None) -> int:
    """
    arguments:
      argv: the command line arguments, including the executable name, like sys.argv
    """
    if not argv:
        argv = sys.argv

    parser = make_parser(argv[1:])
    try:
        args = parser.parse_args(args=argv[1:])
    except ArgumentValueError as e:
        return -1

    set_log_config(args)

    # Since Python 3.8 cp65001 is an alias to utf_8, but not for Python < 3.8
    # TODO: remove this code when only supporting Python 3.8+
    # https://stackoverflow.com/a/3259271/87207
    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    args.expert = args.x
    args.should_show_metainfo = True
    args.quiet = False

    # set defaults when -x is not provided
    args.min_length = args.min_length if hasattr(args, "min_length") else DEFAULT_MIN_LENGTH
    args.functions = args.functions if hasattr(args, "functions") else None
    args.no_filter = args.no_filter if hasattr(args, "no_filter") else False
    args.max_instruction_count = (
        args.max_instruction_count if hasattr(args, "max_instruction_count") else DEFAULT_MAX_INSN_COUNT
    )
    args.max_address_revisits = (
        args.max_address_revisits if hasattr(args, "max_address_revisits") else DEFAULT_MAX_ADDRESS_REVISITS
    )
    args.no_static_strings = args.no_static_strings if hasattr(args, "no_static_strings") else False
    args.no_decoded_strings = args.no_decoded_strings if hasattr(args, "no_decoded_strings") else False
    args.no_stack_strings = args.no_stack_strings if hasattr(args, "no_stack_strings") else False
    args.is_shellcode = args.is_shellcode if hasattr(args, "is_shellcode") else False
    args.shellcode_entry_point = args.shellcode_entry_point if hasattr(args, "shellcode_entry_point") else None
    args.shellcode_base = args.shellcode_base if hasattr(args, "shellcode_base") else None
    args.shellcode_arch = args.shellcode_arch if hasattr(args, "shellcode_arch") else None

    sample = validate_sample_path(parser, args)

    if not is_supported_file_type(sample) and not args.is_shellcode:
        logger.error("FLOSS only supports analyzing PE files or shellcode.\nIf this is shellcode, use the -s switch.")
        return -1

    results = ResultDocument(
        metadata=Metadata(
            file_path=sample,
            enable_stack_strings=not args.no_stack_strings,
            enable_decoded_strings=not args.no_decoded_strings,
            enable_static_strings=not args.no_static_strings,
        )
    )

    # 1. static strings, because its fast
    # 2. decoded strings
    # 3. stack strings

    if results.metadata.enable_static_strings:
        logger.info("extracting static strings...")
        if os.path.getsize(sample) > sys.maxsize:
            logger.warning("file is very large, strings listings may be truncated.")

        with open(sample, "rb") as f:
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                static_ascii_strings = list(strings.extract_ascii_strings(buf, args.min_length))
                static_unicode_strings = list(strings.extract_unicode_strings(buf, args.min_length))

        results.strings.static_strings = static_ascii_strings + static_unicode_strings

        if not args.json:
            print_static_strings(results)

    if results.metadata.enable_decoded_strings or results.metadata.enable_stack_strings:
        if os.path.getsize(sample) > MAX_FILE_SIZE:
            logger.error("cannot deobfuscate strings from files larger than %d bytes", MAX_FILE_SIZE)
            return -1

        try:
            vw = load_vw(
                sample,
                args.is_shellcode,
                args.shellcode_entry_point,
                args.shellcode_base,
                args.shellcode_arch,
            )
        except WorkspaceLoadError as e:
            logger.error("failed to analyze sample: %s", e)
            return -1

        basename = vw.getFileByVa(vw.getEntryPoints()[0])
        if args.is_shellcode:
            assert args.shellcode_base is not None
            results.metadata.imagebase = args.shellcode_base
        else:
            results.metadata.imagebase = vw.getFileMeta(basename, "imagebase")

        try:
            selected_functions = select_functions(vw, args.functions)
        except ValueError as e:
            # failed to find functions in workspace
            logger.error(e.args[0])
            return -1

        logger.debug("selected the following functions: %s", ", ".join(map(hex, sorted(selected_functions))))

        logger.info("analysis summary:")
        for k, v in get_vivisect_meta_info(vw, selected_functions).items():
            logger.info("  %s: %s" % (k, v or "N/A"))

        time0 = time()

        if results.metadata.enable_decoded_strings:
            logger.info("identifying decoding functions...")

            decoding_functions = find_decoding_functions(vw, selected_functions, disable_progress=True)[:10]

            if len(decoding_functions) == 0:
                logger.info("no candidate decoding functions found.")
            else:
                logger.info("candidate decoding functions :")
                for fva, function_data in decoding_functions:
                    logger.info("  - 0x%x: %.3f", fva, function_data["score"])

            logger.info("decoding strings...")
            results.strings.decoded_strings = decode_strings(
                vw,
                list(map(lambda p: p[0], decoding_functions)),
                args.min_length,
                args.no_filter,
                args.max_instruction_count,
                args.max_address_revisits + 1,
            )
            # TODO: The de-duplication process isn't perfect as it is done here and in print_decoding_results and
            #       all of them on non-sanitized strings.
            if not args.no_filter:
                results.strings.decoded_strings = filter_unique_decoded(results.strings.decoded_strings)
            if not args.json:
                print_decoding_results(results.strings.decoded_strings, quiet=args.quiet)

        if results.metadata.enable_stack_strings:
            logger.info("extracting stackstrings...")
            results.strings.stack_strings = list(
                stackstrings.extract_stackstrings(vw, selected_functions, args.min_length, args.no_filter)
            )

            if not args.no_filter:
                # remove duplicate entries
                results.strings.stack_strings = list(set(results.strings.stack_strings))
            if not args.json:
                print_stack_strings(results.strings.stack_strings, quiet=args.quiet)

        time1 = time()
        logger.info("finished execution after %f seconds", (time1 - time0))

        if args.json:
            print(floss.render.json.render(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
