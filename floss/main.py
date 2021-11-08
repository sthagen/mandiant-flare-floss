#!/usr/bin/env python
# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

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
from typing import Set, List, Union, Optional

import halo
import tqdm
import tabulate
import viv_utils
import viv_utils.flirt
from vivisect import VivWorkspace

import floss.logging
import floss.strings as strings
import floss.version
import floss.render.json
import floss.stackstrings as stackstrings
import floss.string_decoder as string_decoder
from floss.const import MAX_FILE_SIZE, DEFAULT_MIN_LENGTH, SUPPORTED_FILE_MAGIC
from floss.utils import hex, get_vivisect_meta_info
from floss.results import Metadata, AddressType, StackString, TightString, DecodedString, ResultDocument, StringEncoding
from floss.version import __version__
from floss.identify import (
    get_top_functions,
    get_functions_with_tightloops,
    find_decoding_function_features,
    get_functions_without_tightloops,
)
from floss.tightstrings import extract_tightstrings

DEFAULT_MAX_INSN_COUNT = 20000
DEFAULT_MAX_ADDRESS_REVISITS = 0

DEFAULT_SHELLCODE_ARCH = "auto"
DEFAULT_SHELLCODE_BASE = 0x1000
DEFAULT_SHELLCODE_ENTRY = 0

SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"
EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")

logger = floss.logging.getLogger("floss")


class WorkspaceLoadError(ValueError):
    pass


def set_vivisect_log_level(level):
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vivisect.base").setLevel(level)
    logging.getLogger("vivisect.impemu").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)
    logging.getLogger("envi.codeflow").setLevel(level)


def decode_strings(
    vw,
    functions: List[int],
    min_length: int,
    no_filter=False,
    max_instruction_count=20000,
    max_hits=1,
    disable_progress=False,
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

    pbar = tqdm.tqdm
    if disable_progress:
        # do not use tqdm to avoid unnecessary side effects when caller intends
        # to disable progress completely
        pbar = lambda s, *args, **kwargs: s

    pb = pbar(functions, desc="decoding strings", unit=" functions")
    for fva in pb:
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
    desc = "The FLARE team's open-source tool to extract obfuscated strings from malware.\n  %(prog)s {:s} - https://github.com/mandiant/flare-floss/".format(
        __version__
    )
    epilog = textwrap.dedent(
        """
        only displaying core arguments, run `floss --help -x` to see all supported arguments

        examples:
          extract all strings from an executable
            floss suspicious.exe

          extract all strings from 32-bit shellcode
            floss -f sc32 shellcode.bin
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

    formats = [
        ("auto", "(default) detect file type automatically"),
        ("pe", "Windows PE file"),
        ("sc32", "32-bit shellcode"),
        ("sc64", "64-bit shellcode"),
    ]
    format_help = ", ".join(["%s: %s" % (f[0], f[1]) for f in formats])
    parser.add_argument(
        "-f",
        "--format",
        choices=[f[0] for f in formats],
        default="auto",
        help="select sample format, %s" % format_help,
    )

    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        default=DEFAULT_MIN_LENGTH,
        help="minimum string length" if expert else argparse.SUPPRESS,
    )

    parser.add_argument(
        "--signatures",
        type=str,
        default=SIGNATURES_PATH_DEFAULT_STRING,
        help="path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default"
        if expert
        else argparse.SUPPRESS,
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

    # TODO move group to first position
    analysis_group = parser.add_argument_group("analysis arguments")
    analysis_group.add_argument(
        "--functions",
        type=lambda x: int(x, 0x10),
        default=None,
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
        type=int,
        default=DEFAULT_MAX_ADDRESS_REVISITS,
        help="maximum number of address revisits per function" if expert else argparse.SUPPRESS,
    )

    analysis_group.add_argument(
        "--no-static-strings",
        action="store_true",
        default=False,
        help="do not show static ASCII and UTF-16 strings" if expert else argparse.SUPPRESS,
    )
    analysis_group.add_argument(
        "--no-decoded-strings",
        action="store_true",
        default=False,
        help="do not show decoded strings" if expert else argparse.SUPPRESS,
    )
    analysis_group.add_argument(
        "--no-stack-strings",
        action="store_true",
        default=False,
        help="do not show stackstrings" if expert else argparse.SUPPRESS,
    )
    analysis_group.add_argument(
        "--no-tight-strings",
        action="store_true",
        default=False,
        help="do not show tightstrings" if expert else argparse.SUPPRESS,
    )

    output_group = parser.add_argument_group("rendering arguments")
    output_group.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    output_group.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose result document (no effect with --json)"
    )
    output_group.add_argument(
        "-vv", "--vverbose", action="store_true", help="enable very verbose result document (no effect with --json)"
    )
    # TODO currently unused
    output_group.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )

    logging_group = parser.add_argument_group("logging arguments")

    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument("-dd", "--trace", action="store_true", help="enable verbose debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    return parser


def set_log_config(args):
    if args.quiet:
        log_level = logging.WARNING
    elif args.trace:
        log_level = logging.TRACE
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    # TODO enable and do more testing
    # disable vivisect-related logging, it's verbose and not relevant for FLOSS users
    set_vivisect_log_level(logging.CRITICAL)

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
        logger.debug("selected ALL functions")
        return functions

    asked_functions_ = set(asked_functions or [])

    # validate that all functions requested by the user exist.
    missing_functions = sorted(asked_functions_ - functions)
    if missing_functions:
        raise ValueError("failed to find functions: %s" % (", ".join(map(hex, sorted(missing_functions)))))

    logger.debug(f"selected %d functions", len(asked_functions_))
    logger.trace("selected the following functions: %s", ", ".join(map(hex, sorted(asked_functions_))))

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


def print_stack_strings(extracted_strings: Union[List[StackString], List[TightString]], quiet=False):
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
    logger.trace("analysis summary:")
    for k, v in get_vivisect_meta_info(vw, selected_functions).items():
        logger.trace("  %s: %s" % (k, v or "N/A"))


class Architecture(str, Enum):
    i386 = "i386"
    amd64 = "amd64"


def load_vw(
    sample_path: str,
    format: str,
    sigpaths: str,
    should_save_workspace: bool = False,
) -> VivWorkspace:

    if format not in ("sc32", "sc64"):
        if not is_supported_file_type(sample_path):
            raise WorkspaceLoadError(
                "FLOSS currently supports the following formats for string decoding and stackstrings: PE\n"
                "You can analyze shellcode using the --format sc32|sc64 switch. See the help (-h) for more information."
            )

    # get shellcode type based on sample file extension
    if format == "auto" and sample_path.endswith(EXTENSIONS_SHELLCODE_32):
        format = "sc32"
    elif format == "auto" and sample_path.endswith(EXTENSIONS_SHELLCODE_64):
        format = "sc64"

    if format == "sc32":
        vw = viv_utils.getShellcodeWorkspaceFromFile(sample_path, arch="i386", analyze=False)
    elif format == "sc64":
        vw = viv_utils.getShellcodeWorkspaceFromFile(sample_path, arch="amd64", analyze=False)
    else:
        vw = viv_utils.getWorkspace(sample_path, analyze=False, should_save=False)

    viv_utils.flirt.register_flirt_signature_analyzers(vw, sigpaths)

    vw.analyze()

    if should_save_workspace:
        logger.debug("saving workspace")
        try:
            vw.saveWorkspace()
        except IOError:
            logger.info("source directory is not writable, won't save intermediate workspace")
    else:
        logger.debug("not saving workspace")

    return vw


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


def get_default_root() -> str:
    """
    get the file system path to the default resources directory.
    under PyInstaller, this comes from _MEIPASS.
    under source, this is the root directory of the project.
    """
    if is_running_standalone():
        # pylance/mypy don't like `sys._MEIPASS` because this isn't standard.
        # its injected by pyinstaller.
        # so we'll fetch this attribute dynamically.
        return getattr(sys, "_MEIPASS")
    else:
        return os.path.join(os.path.dirname(__file__), "..")


def get_signatures(sigs_path):
    if not os.path.exists(sigs_path):
        raise IOError("signatures path %s does not exist or cannot be accessed" % sigs_path)

    paths = []
    if os.path.isfile(sigs_path):
        paths.append(sigs_path)
    elif os.path.isdir(sigs_path):
        logger.debug("reading signatures from directory %s", os.path.abspath(os.path.normpath(sigs_path)))
        for root, dirs, files in os.walk(sigs_path):
            for file in files:
                if file.endswith((".pat", ".pat.gz", ".sig")):
                    sig_path = os.path.join(root, file)
                    paths.append(sig_path)

    # nicely normalize and format path so that debugging messages are clearer
    paths = [os.path.abspath(os.path.normpath(path)) for path in paths]

    # load signatures in deterministic order: the alphabetic sorting of filename.
    # this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths = sorted(paths, key=os.path.basename)

    for path in paths:
        logger.debug("found signature file: %s", path)

    return paths


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

    if hasattr(args, "signatures"):
        if args.signatures == SIGNATURES_PATH_DEFAULT_STRING:
            logger.debug("-" * 80)
            logger.debug(" Using default embedded signatures.")
            logger.debug(
                " To provide your own signatures, use the form `floss.exe --signature ./path/to/signatures/  /path/to/mal.exe`."
            )
            logger.debug("-" * 80)

            sigs_path = os.path.join(get_default_root(), "sigs")
        else:
            sigs_path = args.signatures
            logger.debug("using signatures path: %s", sigs_path)

        args.signatures = sigs_path

    sample = validate_sample_path(parser, args)

    results = ResultDocument(
        metadata=Metadata(
            file_path=sample,
            enable_stack_strings=not args.no_stack_strings,
            enable_tight_strings=not args.no_tight_strings,
            enable_decoded_strings=not args.no_decoded_strings,
            enable_static_strings=not args.no_static_strings,
        )
    )

    # 1. static strings, because its fast
    # 2. decoded strings
    # 3. stack strings  # TODO move to 2. since it's also fast
    # 4. tight strings

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

    if (
        results.metadata.enable_decoded_strings
        or results.metadata.enable_stack_strings
        or results.metadata.enable_tight_strings
    ):
        if os.path.getsize(sample) > MAX_FILE_SIZE:
            logger.error("cannot deobfuscate strings from files larger than %d bytes", MAX_FILE_SIZE)
            return -1

        sigpaths = get_signatures(args.signatures)

        should_save_workspace = os.environ.get("FLOSS_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        try:
            with halo.Halo(text="analyzing program", spinner="simpleDots", stream=sys.stderr, enabled=not args.quiet):
                vw = load_vw(sample, args.format, sigpaths, should_save_workspace)
        except WorkspaceLoadError as e:
            logger.error("failed to analyze sample: %s", e)
            return -1

        basename = vw.getFileByVa(vw.getEntryPoints()[0])
        results.metadata.imagebase = vw.getFileMeta(basename, "imagebase")

        try:
            selected_functions = select_functions(vw, args.functions)
        except ValueError as e:
            # failed to find functions in workspace
            logger.error(e.args[0])
            return -1

        logger.trace("analysis summary:")
        for k, v in get_vivisect_meta_info(vw, selected_functions).items():
            logger.trace("  %s: %s" % (k, v or "N/A"))

        time0 = time()

        logger.info("identifying decoding function features...")
        decoding_function_features, meta_lib_funcs = find_decoding_function_features(
            vw, selected_functions, disable_progress=args.quiet
        )
        results.metadata.analysis.update(meta_lib_funcs)

        if results.metadata.enable_decoded_strings:
            top_functions = get_top_functions(decoding_function_features, 20)
            # TODO also emulate tightfuncs that have a tight loop and are short < 5 BBs

            if len(top_functions) == 0:
                logger.info("no candidate decoding functions found.")
            else:
                logger.info("identified %d candidate decoding functions", len(top_functions))
                for fva, function_data in top_functions:
                    logger.debug("  - 0x%x: %.3f", fva, function_data["score"])

            logger.info("decoding strings...")
            results.strings.decoded_strings = decode_strings(
                vw,
                list(map(lambda p: p[0], top_functions)),
                args.min_length,
                False,
                args.max_instruction_count,
                args.max_address_revisits + 1,
                disable_progress=args.quiet,
            )
            # TODO: The de-duplication process isn't perfect as it is done here and in print_decoding_results and
            #       all of them on non-sanitized strings.
            results.strings.decoded_strings = filter_unique_decoded(results.strings.decoded_strings)
            if not args.json:
                print_decoding_results(results.strings.decoded_strings, quiet=args.quiet)

        if results.metadata.enable_stack_strings:
            # don't run this on functions with tight loops as this will likely result in FPs
            # and should be caught by the tightstrings extraction below
            no_tightloop_functions = get_functions_without_tightloops(decoding_function_features)

            logger.info("extracting stackstrings...")
            results.strings.stack_strings = list(
                stackstrings.extract_stackstrings(vw, no_tightloop_functions, args.min_length, quiet=args.quiet)
            )

            # remove duplicate entries
            results.strings.stack_strings = list(set(results.strings.stack_strings))
            if not args.json:
                print_stack_strings(results.strings.stack_strings, quiet=args.quiet)

        if results.metadata.enable_tight_strings:
            logger.info("extracting tightstrings...")
            tightloop_functions = get_functions_with_tightloops(decoding_function_features)
            # TODO if there are many tight loop functions, emit that the program likely uses tightstrings? see #400
            results.strings.tight_strings = list(extract_tightstrings(vw, tightloop_functions, quiet=args.quiet))

            if not args.json:
                print_stack_strings(results.strings.tight_strings, quiet=args.quiet)

        time1 = time()
        logger.info("finished execution after %f seconds", (time1 - time0))

        if args.json:
            print(floss.render.json.render(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
