#!/usr/bin/env python
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import os
import sys
import mmap
import string
import logging
import argparse
from time import time
from typing import Set, List, Iterator
from itertools import chain

import tabulate
import viv_utils

import floss.strings as strings
import floss.version
import floss.render.json
import floss.stackstrings as stackstrings
import floss.render.logging
import floss.string_decoder as string_decoder
import floss.identification_manager as im
from floss.const import MAX_FILE_SIZE, DEFAULT_MIN_LENGTH, SUPPORTED_FILE_MAGIC
from floss.utils import hex, get_vivisect_meta_info
from floss.version import __version__
from floss.render.result_document import Metadata, AddressType, StackString, DecodedString, ResultDocument

logger = logging.getLogger("floss")


class LoadNotSupportedError(Exception):
    pass


class WorkspaceLoadError(Exception):
    pass


def decode_strings(
    vw, decoding_functions_candidates, min_length, no_filter=False, max_instruction_count=20000, max_hits=1
) -> List[DecodedString]:
    """
    FLOSS string decoding algorithm
    :param vw: vivisect workspace
    :param decoding_functions_candidates: identification manager
    :param min_length: minimum string length
    :param no_filter: do not filter decoded strings
    :param max_instruction_count: The maximum number of instructions to emulate per function.
    :param max_hits: The maximum number of hits per address
    :return: list of decoded strings ([DecodedString])
    """
    decoded_strings = []
    function_index = viv_utils.InstructionFunctionIndex(vw)
    # TODO pass function list instead of identification manager
    for fva, _ in decoding_functions_candidates.get_top_candidate_functions(10):
        for ctx in string_decoder.extract_decoding_contexts(vw, fva, max_hits):
            for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx, max_instruction_count):
                for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                    for decoded_string in string_decoder.extract_strings(delta_bytes, min_length, no_filter):
                        decoded_strings.append(decoded_string)
    return decoded_strings


def sanitize_strings_iterator(str_coll: Iterator[DecodedString]) -> str:
    """
    Iterate a collection and yield sanitized strings (uses sanitize_string_for_printing)
    :param str_coll: collection of strings to be sanitized
    :return: a sanitized string
    """
    for s_obj in str_coll:
        s = getattr(s_obj, "s", s_obj)  # Use .s attribute from each namedtuple if possible
        yield sanitize_string_for_printing(s)


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


def make_parser(argv):
    usage_message = "floss [options] FILEPATH"

    parser = argparse.ArgumentParser(
        usage=usage_message, description="floss {:s}\nhttps://github.com/fireeye/flare-floss/".format(__version__)
    )

    parser.add_argument("-x", action="store_true", dest="x", help="enable eXpert arguments, try `floss --help -x`")

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

    if "-x" in argv:
        analysis_group = parser.add_argument_group("analysis arguments")
        analysis_group.add_argument(
            "--minimum-length",
            dest="min_length",
            default=DEFAULT_MIN_LENGTH,
            help="minimum string length",
        )

        # TODO: make this a list
        analysis_group.add_argument(
            "--functions",
            help="only analyze the specified functions (comma-separated)",
            type=str,
        )

        analysis_group.add_argument(
            "--no-filter",
            action="store_true",
            help="do not filter deobfuscated strings (may result in many false positive strings)",
        )

        analysis_group.add_argument(
            "--max-instruction-count",
            type=int,
            default=DEFAULT_MAX_INSN_COUNT,
            help="maximum number of instructions to emulate per function",
        )

        analysis_group.add_argument(
            "--max-address-revisits",
            dest="max_address_revisits",
            type=int,
            default=DEFAULT_MAX_ADDRESS_REVISITS,
            help="maximum number of address revisits per function",
        )

        analysis_group.add_argument(
            "--no-static-strings",
            dest="no_static_strings",
            action="store_true",
            help="do not show static ASCII and UTF-16 strings",
        )
        analysis_group.add_argument(
            "--no-decoded-strings", dest="no_decoded_strings", action="store_true", help="do not show decoded strings"
        )
        analysis_group.add_argument(
            "--no-stack-strings", dest="no_stack_strings", action="store_true", help="do not show stackstrings"
        )

        shellcode_group = parser.add_argument_group("shellcode arguments")
        shellcode_group.add_argument(
            "-s", "--shellcode", dest="is_shellcode", help="analyze shellcode", action="store_true"
        )
        shellcode_group.add_argument(
            "-e", "--shellcode_ep", dest="shellcode_entry_point", help="shellcode entry point", type=str
        )
        shellcode_group.add_argument(
            "-b", "--shellcode_base", dest="shellcode_base", help="shellcode base offset", type=str
        )

    return parser


def set_log_config(args):
    if args.quiet:
        log_level = logging.WARNING
        emulator_driver_level = logging.CRITICAL
    elif args.debug:
        log_level = logging.DEBUG
        emulator_driver_level = logging.DEBUG
    else:
        log_level = logging.INFO
        emulator_driver_level = logging.INFO

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    # install the log message colorizer to the default handler.
    # because basicConfig is just above this,
    # handlers[0] is a StreamHandler to STDERR.
    #
    # calling this code from outside script main may do something unexpected.
    logging.getLogger().handlers[0].setFormatter(floss.render.logging.ColorFormatter())

    # TODO: can we remove all this junk?

    # ignore messages like:
    # DEBUG: mapping section: 0 .text
    logging.getLogger("vivisect.parsers.pe").setLevel(log_level)

    # ignore messages like:
    # WARNING:EmulatorDriver:error during emulation of function: BreakpointHit at 0x1001fbfb
    # ERROR:EmulatorDriver:error during emulation of function ... DivideByZero: DivideByZero at 0x10004940
    # TODO: probably should modify emulator driver to de-prioritize this
    logging.getLogger("EmulatorDriver").setLevel(emulator_driver_level)

    # ignore messages like:
    # WARNING:Monitor:logAnomaly: anomaly: BreakpointHit at 0x1001fbfb
    logging.getLogger("Monitor").setLevel(log_level)

    # ignore messages like:
    # WARNING:envi/codeflow.addCodeFlow:parseOpcode error at 0x1001044c: InvalidInstruction("'660f3a0fd90c660f7f1f660f6fe0660f' at 0x1001044c",)
    logging.getLogger("envi/codeflow.addCodeFlow").setLevel(log_level)

    # ignore messages like:
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\symsrv.dll: [Error 126] The specified module could not be found
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\dbghelp.dll: [Error 126] The specified module could not be found
    logging.getLogger("vtrace.platforms.win32").setLevel(log_level)

    # ignore messages like:
    # DEBUG: merge_candidates: Function at 0x00401500 is new, adding
    logging.getLogger("floss.identification_manager.IdentificationManager").setLevel(log_level)

    # ignore messages like:
    # WARNING: get_caller_vas: unknown caller function: 0x403441
    # DEBUG: get_all_function_contexts: Getting function context for function at 0x00401500...
    logging.getLogger("floss.function_argument_getter.FunctionArgumentGetter").setLevel(log_level)

    # ignore messages like:
    # DEBUG: Emulating function at 0x004017A9 called at 0x00401644, return address: 0x00401649
    logging.getLogger("floss").setLevel(log_level)

    # ignore messages like:
    # DEBUG: extracting stackstrings at checkpoint: 0x4048dd stacksize: 0x58
    logging.getLogger("floss.stackstrings").setLevel(log_level)

    # ignore messages like:
    # WARNING:plugins.arithmetic_plugin.XORPlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
    logging.getLogger("floss.plugins.arithmetic_plugin.XORPlugin").setLevel(log_level)
    logging.getLogger("floss.plugins.arithmetic_plugin.ShiftPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Identified WSAStartup_00401476 at VA 0x00401476
    logging.getLogger("floss.plugins.library_function_plugin.FunctionIsLibraryPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Function at 0x00401500: Cross references to: 2
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionCrossReferencesToPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Function at 0x00401FFF: Number of arguments: 3
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionArgumentCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401470 has meta data: Thunk: ws2_32.WSACleanup
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionIsThunkPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: BlockCount: 7
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionBlockCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: InstructionCount: 60
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionInstructionCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: Size: 177
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionSizePlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: suspicious MOV instruction at 0x00401017 in function 0x00401000: mov byte [edx],al
    logging.getLogger("floss.plugins.mov_plugin.MovPlugin").setLevel(log_level)


def parse_functions_option(functions_option):
    """
    Return parsed -f command line option or None.
    """
    fvas = None
    if functions_option:
        fvas = [int(fva, 0x10) for fva in functions_option.split(",")]
    return fvas


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


def select_functions(vw, functions_option) -> Set[int]:
    """
    Given a workspace and sequence of function addresses, return the set
    of valid functions, or all valid function addresses.
    :param vw: vivisect workspace
    :param functions_option: -f command line option
    :return: list of all valid function addresses
    """
    function_vas = parse_functions_option(functions_option)

    workspace_functions = set(vw.getFunctions())
    if function_vas is None:
        return workspace_functions

    function_vas = set(function_vas)
    if len(function_vas - workspace_functions) > 0:
        raise Exception(
            "Functions don't exist in vivisect workspace: %s"
            % get_str_from_func_list(list(function_vas - workspace_functions))
        )

    return function_vas


def get_str_from_func_list(function_list):
    return ", ".join(map(hex, function_list))


def filter_unique_decoded(decoded_strings):
    unique_values = set()
    originals = []
    for decoded in decoded_strings:
        hashable = (decoded.string, decoded.decoded_at, decoded.decoding_routine)
        if hashable not in unique_values:
            unique_values.add(hashable)
            originals.append(decoded)
    return originals


def parse_min_length_option(min_length_option):
    """
    Return parsed -n command line option or default length.
    """
    min_length = int(min_length_option or str(DEFAULT_MIN_LENGTH))
    return min_length


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


def print_identification_results(sample_file_path, decoder_results):
    """
    Print results of string decoding routine identification phase.
    :param sample_file_path: input file
    :param decoder_results: identification_manager
    """
    # TODO pass functions instead of identification_manager
    candidates = decoder_results.get_top_candidate_functions(10)
    if len(candidates) == 0:
        print("No candidate functions found.")
    else:
        print("Most likely decoding functions in: " + sample_file_path)
        print(
            tabulate.tabulate(
                [(hex(fva), "%.5f" % (score,)) for fva, score in candidates], headers=["address", "score"]
            )
        )


def print_decoding_results(decoded_strings: List[DecodedString], group_functions, quiet=False, expert=False):
    """
    Print results of string decoding phase.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param group_functions: group output by VA of decoding routines
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """

    if group_functions:
        if not quiet:
            print("\nFLOSS decoded %d strings" % len(decoded_strings))
        fvas = set([i.decoding_routine for i in decoded_strings])
        for fva in fvas:
            grouped_strings = [ds for ds in decoded_strings if ds.decoding_routine == fva]
            len_ds = len(grouped_strings)
            if len_ds > 0:
                if not quiet:
                    print("\nDecoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                print_decoded_strings(grouped_strings, quiet=quiet, expert=expert)
    else:
        if not expert:
            seen = set()
            decoded_strings = [x for x in decoded_strings if not (x.string in seen or seen.add(x.string))]
        if not quiet:
            print("\nFLOSS decoded %d strings" % len(decoded_strings))

        print_decoded_strings(decoded_strings, quiet=quiet, expert=expert)


def print_decoded_strings(decoded_strings: List[DecodedString], quiet=False, expert=False):
    """
    Print decoded strings.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """
    if quiet or not expert:
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


def print_static_strings(file_buf, min_length, quiet=False):
    """
    Print static ASCII and UTF-16 strings from provided file.
    :param file_buf: the file buffer
    :param min_length: minimum string length
    :param quiet: print strings only, suppresses headers
    """
    static_ascii_strings = strings.extract_ascii_strings(file_buf, min_length)
    static_unicode_strings = strings.extract_unicode_strings(file_buf, min_length)

    if not quiet:
        print("FLOSS static ASCII strings")
    for s in static_ascii_strings:
        print("%s" % s.string)
    if not quiet:
        print("")

    if not quiet:
        print("FLOSS static Unicode strings")
    for s in static_unicode_strings:
        print("%s" % s.string)
    if not quiet:
        print("")


def print_stack_strings(extracted_strings: List[StackString], quiet=False, expert=False):
    """
    Print extracted stackstrings.
    :param extracted_strings: list of stack strings ([StackString])
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """
    count = len(extracted_strings)

    if not quiet:
        print("\nFLOSS extracted %d stackstrings" % (count))

    if not expert:
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
    print("\nVivisect workspace analysis information")
    try:
        for k, v in get_vivisect_meta_info(vw, selected_functions).items():
            print("%s: %s" % (k, v or "N/A"))  # display N/A if value is None
    except Exception as e:
        logger.error("Failed to print vivisect analysis information: %s}", str(e))


def load_workspace(sample_file_path, save_workspace):
    # inform user that getWorkspace implicitly loads saved workspace if .viv file exists
    if is_workspace_file(sample_file_path) or os.path.exists("%s.viv" % sample_file_path):
        logger.info("Loading existing vivisect workspace...")
    else:
        if not is_supported_file_type(sample_file_path):
            raise LoadNotSupportedError(
                "FLOSS currently supports the following formats for string decoding and "
                "stackstrings: PE\nYou can analyze shellcode using the -s switch. See the "
                "help (-h) for more information."
            )
        logger.info("Generating vivisect workspace...")
    return viv_utils.getWorkspace(sample_file_path, should_save=save_workspace)


def load_shellcode_workspace(sample_file_path, save_workspace, shellcode_ep_in, shellcode_base_in):
    if is_supported_file_type(sample_file_path):
        logger.warning("Analyzing supported file type as shellcode. This will likely yield weaker analysis.")

    shellcode_entry_point = 0
    if shellcode_ep_in:
        shellcode_entry_point = int(shellcode_ep_in, 0x10)

    shellcode_base = 0
    if shellcode_base_in:
        shellcode_base = int(shellcode_base_in, 0x10)

    logger.info(
        "Generating vivisect workspace for shellcode, base: 0x%x, entry point: 0x%x...",
        shellcode_base,
        shellcode_entry_point,
    )
    with open(sample_file_path, "rb") as f:
        shellcode_data = f.read()
    return viv_utils.getShellcodeWorkspace(
        shellcode_data, "i386", shellcode_base, shellcode_entry_point, save_workspace, sample_file_path
    )


def load_vw(sample_file_path, save_workspace, verbose, is_shellcode, shellcode_entry_point, shellcode_base):
    try:
        if not is_shellcode:
            if shellcode_entry_point or shellcode_base:
                logger.warning(
                    "Entry point and base offset only apply in conjunction with the -s switch when "
                    "analyzing raw binary files."
                )
            return load_workspace(sample_file_path, save_workspace)
        else:
            return load_shellcode_workspace(sample_file_path, save_workspace, shellcode_entry_point, shellcode_base)
    except LoadNotSupportedError as e:
        logger.error(str(e))
        raise WorkspaceLoadError
    except Exception as e:
        logger.error("Vivisect failed to load the input file: %s", str(e), exc_info=verbose)
        raise WorkspaceLoadError


def main(argv=None):
    """
    :param argv: optional command line arguments, like sys.argv[1:]
    :return: 0 on success, non-zero on failure
    """
    if not argv:
        argv = sys.argv[1:]

    parser = make_parser(argv)
    args = parser.parse_args(args=argv)

    set_log_config(args)

    # Since Python 3.8 cp65001 is an alias to utf_8, but not for Python < 3.8
    # TODO: remove this code when only supporting Python 3.8+
    # https://stackoverflow.com/a/3259271/87207
    import codecs

    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    # expert profile settings
    # TODO: removeme
    args.expert = args.x
    args.should_show_metainfo = True
    args.save_workspace = True
    args.group_functions = True
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

    sample_file_path = validate_sample_path(parser, args)

    result_document = ResultDocument(
        metadata=Metadata(
            file_path=sample_file_path,
            enable_stack_strings=not args.no_stack_strings,
            enable_decoded_strings=not args.no_decoded_strings,
            enable_static_strings=not args.no_static_strings,
        )
    )

    if not is_workspace_file(sample_file_path):
        if not args.no_static_strings and not args.functions:
            logger.info("Extracting static strings...")
            if os.path.getsize(sample_file_path) > sys.maxsize:
                logger.warning("File too large, strings listings may be truncated.")
                logger.warning("FLOSS cannot handle files larger than 4GB on 32bit systems.")

            file_buf = get_file_as_mmap(sample_file_path)
            if not args.json:
                print_static_strings(file_buf, min_length=args.min_length, quiet=args.quiet)
            static_ascii_strings = strings.extract_ascii_strings(file_buf, args.min_length)
            static_unicode_strings = strings.extract_unicode_strings(file_buf, args.min_length)
            result_document.strings.static_strings = list(chain(static_ascii_strings, static_unicode_strings))
            del file_buf

        if args.no_decoded_strings and args.no_stack_strings and not args.should_show_metainfo:
            if args.json:
                print(floss.render.json.render(result_document))
            # we are done
            return 0

    if os.path.getsize(sample_file_path) > MAX_FILE_SIZE:
        logger.error(
            "FLOSS cannot extract obfuscated strings or stackstrings from files larger than" " %d bytes" % MAX_FILE_SIZE
        )
        if args.json:
            print(floss.render.json.render(result_document))
        return 1

    try:
        vw = load_vw(
            sample_file_path,
            args.save_workspace,
            args.verbose,
            args.is_shellcode,
            args.shellcode_entry_point,
            args.shellcode_base,
        )
    except WorkspaceLoadError:
        if args.json:
            print(floss.render.json.render(result_document))
        return 1

    basename = vw.getFileByVa(vw.getEntryPoints()[0])
    result_document.metadata.imagebase = vw.getFileMeta(basename, "imagebase")

    try:
        selected_functions = select_functions(vw, args.functions)
    except Exception as e:
        logger.error(str(e))
        return 1

    logger.debug("Selected the following functions: %s", get_str_from_func_list(selected_functions))

    if args.should_show_metainfo:
        meta_functions = set()
        if args.functions:
            meta_functions = selected_functions

        if not args.json:
            print_file_meta_info(vw, meta_functions)

    time0 = time()

    if not args.no_decoded_strings:
        logger.info("Identifying decoding functions...")
        decoding_functions_candidates = im.identify_decoding_functions(vw, selected_functions)
        if args.expert:
            if not args.json:
                print_identification_results(sample_file_path, decoding_functions_candidates)

        logger.info("Decoding strings...")
        result_document.strings.decoded_strings = decode_strings(
            vw,
            decoding_functions_candidates,
            args.min_length,
            args.no_filter,
            args.max_instruction_count,
            args.max_address_revisits + 1,
        )
        # TODO: The de-duplication process isn't perfect as it is done here and in print_decoding_results and
        # TODO: all of them on non-sanitized strings.
        if not args.expert:
            result_document.strings.decoded_strings = filter_unique_decoded(result_document.strings.decoded_strings)
        if not args.json:
            print_decoding_results(
                result_document.strings.decoded_strings, args.group_functions, quiet=args.quiet, expert=args.expert
            )

    if not args.no_stack_strings:
        logger.info("Extracting stackstrings...")
        result_document.strings.stack_strings = list(
            stackstrings.extract_stackstrings(vw, selected_functions, args.min_length, args.no_filter)
        )
        if not args.expert:
            # remove duplicate entries
            result_document.strings.stack_strings = list(set(result_document.strings.stack_strings))
        if not args.json:
            print_stack_strings(result_document.strings.stack_strings, quiet=args.quiet, expert=args.expert)

    time1 = time()
    logger.info("\nFinished execution after %f seconds", (time1 - time0))

    if args.json:
        print(floss.render.json.render(result_document))

    return 0


if __name__ == "__main__":
    sys.exit(main())
