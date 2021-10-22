# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.
import re
import time
import inspect
import logging
import contextlib
from collections import OrderedDict

import tqdm
import tabulate
from envi import Emulator

from .const import MEGABYTE

STACK_MEM_NAME = "[stack]"


logger = logging.getLogger(__name__)


def make_emulator(vw) -> Emulator:
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\xFE")
    remove_stack_memory(emu)
    emu.initStackMemory(stacksize=int(0.5 * MEGABYTE))
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * MEGABYTE))
    # do not short circuit rep prefix
    try:
        emu.setEmuOpt("i386:repmax", 256)  # 0 == no limit on rep prefix
    except Exception:
        # TODO remove once vivisect#465 is included in release
        emu.setEmuOpt("i386:reponce", False)
    return emu


def remove_stack_memory(emu: Emulator):
    # TODO this is a hack while vivisect's initStackMemory() has a bug (see issue #27)
    # TODO does this bug still exist?
    memory_snap = emu.getMemorySnap()
    for i in range((len(memory_snap) - 1), -1, -1):
        (_, _, info, _) = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            return
    raise ValueError("`STACK_MEM_NAME` not in memory map")


def get_vivisect_meta_info(vw, selected_functions):
    info = OrderedDict()
    entry_points = vw.getEntryPoints()
    basename = None
    if entry_points:
        basename = vw.getFileByVa(entry_points[0])

    # "blob" is the filename for shellcode
    if basename and basename != "blob":
        version = vw.getFileMeta(basename, "Version")
        md5sum = vw.getFileMeta(basename, "md5sum")
        baseva = hex(vw.getFileMeta(basename, "imagebase"))
    else:
        version = "N/A"
        md5sum = "N/A"
        baseva = "N/A"

    info["version"] = version
    info["MD5 Sum"] = md5sum
    info["format"] = vw.getMeta("Format")
    info["architecture"] = vw.getMeta("Architecture")
    info["platform"] = vw.getMeta("Platform")
    disc = vw.getDiscoveredInfo()[0]
    undisc = vw.getDiscoveredInfo()[1]
    info["percentage of discovered executable surface area"] = "%.1f%% (%s / %s)" % (
        disc * 100.0 / (disc + undisc),
        disc,
        disc + undisc,
    )
    info["base VA"] = baseva
    info["entry point(s)"] = ", ".join(map(hex, entry_points))
    info["number of imports"] = len(vw.getImports())
    info["number of exports"] = len(vw.getExports())
    info["number of functions"] = len(vw.getFunctions())

    if selected_functions:
        meta = []
        for fva in selected_functions:
            xrefs_to = len(vw.getXrefsTo(fva))
            num_args = len(vw.getFunctionArgs(fva))
            function_meta = vw.getFunctionMetaDict(fva)
            instr_count = function_meta.get("InstructionCount")
            block_count = function_meta.get("BlockCount")
            size = function_meta.get("Size")
            meta.append((hex(fva), xrefs_to, num_args, size, block_count, instr_count))
        info["selected functions' info"] = "\n%s" % tabulate.tabulate(
            meta, headers=["fva", "#xrefs", "#args", "size", "#blocks", "#instructions"]
        )

    return info


def hex(i):
    return "0x%X" % (i)


FP_FILTER_PREFIXES = re.compile(r"^.?((p|P|0)?VA)|(0|P)?\\A|\[A|P\]A|@AA")  # remove string prefixes: pVA, VA, 0VA, etc.
FP_FILTER_SUFFIXES = re.compile(
    r"([0-9A-G>]VA|@AA|iiVV|j=p@|ids@|iDC@|i4C@|i%1@)$"
)  # remove string suffixes: 0VA, AVA, >VA, etc.
FP_FILTER_CHARS = re.compile(r".*(AAA|BBB|CCC|DDD|EEE|FFF|PPP|UUU|ZZZ|@@@|;;;|&&&|\?\?\?|\|\|\||    ).*")
# alternatively: ".*([^0-9wW])\1{2}.*" to match any 3 consecutive chars (except numbers, ws, and others?)
FP_FILTER_REP_CHARS = re.compile(r".*(.)\1{7}.*")  # any string containing the same char 8 or more consecutive times


def is_fp_string(s):
    """
    Return True if string matches a well-known FP pattern.
    :param s: input string
    """
    for reg in (FP_FILTER_CHARS, FP_FILTER_REP_CHARS):
        if reg.match(s):
            return True
    return False


def strip_string(s):
    """
    Return string stripped from false positive (FP) pre- or suffixes.
    :param s: input string
    :return: string stripped from FP pre- or suffixes
    """
    for reg in (FP_FILTER_PREFIXES, FP_FILTER_SUFFIXES):
        s = re.sub(reg, "", s)
    return s


@contextlib.contextmanager
def redirecting_print_to_tqdm():
    """
    tqdm (progress bar) expects to have fairly tight control over console output.
    so calls to `print()` will break the progress bar and make things look bad.
    so, this context manager temporarily replaces the `print` implementation
    with one that is compatible with tqdm.
    via: https://stackoverflow.com/a/42424890/87207
    """
    old_print = print

    def new_print(*args, **kwargs):

        # If tqdm.tqdm.write raises error, use builtin print
        try:
            tqdm.tqdm.write(*args, **kwargs)
        except:
            old_print(*args, **kwargs)

    try:
        # Globaly replace print with new_print
        inspect.builtins.print = new_print
        yield
    finally:
        inspect.builtins.print = old_print


@contextlib.contextmanager
def timing(msg):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)
