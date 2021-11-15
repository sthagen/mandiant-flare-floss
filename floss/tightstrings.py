from itertools import chain

import tqdm
import viv_utils
import tqdm.contrib.logging

import floss.utils
import floss.features.features
from floss import stackstrings
from floss.results import TightString, StaticString
from floss.strings import extract_ascii_strings, extract_unicode_strings
from floss.stackstrings import StackstringContextMonitor

logger = floss.logging.getLogger(__name__)


class TightstringContextMonitor(StackstringContextMonitor):
    def __init__(self, vw, sp, tloops):
        super(TightstringContextMonitor, self).__init__(vw, sp, [])
        self.tloop_startvas = [t.startva for t in tloops]
        self.tloop_endvas = [t.endva for t in tloops]
        # store FP stackstrings before tightstring loop executes
        self.pre_ctx_strings = set()
        logger.trace(" stavas: %s", ", ".join(map(hex, self.tloop_startvas)))
        logger.trace(" endvas: %s", ", ".join(map(hex, self.tloop_endvas)))

    def apicall(self, emu, op, pc, api, argv):
        pass

    def prehook(self, emu, op, startpc):
        if startpc in self.tloop_startvas:
            try:
                stack_buf = self.get_call_context(emu, op).stack_memory
            except ValueError as e:
                logger.debug(str(e))
                return

            self.pre_ctx_strings.update(map(lambda s: s.string, floss.strings.extract_ascii_strings(stack_buf)))
            self.pre_ctx_strings.update(map(lambda s: s.string, floss.strings.extract_unicode_strings(stack_buf)))

            # only save one context per tightloop
            self.tloop_startvas.remove(startpc)

    def posthook(self, emu, op, endpc):
        if endpc in self.tloop_endvas:
            logger.trace("extracting context at endpc: 0x%x", endpc)
            self.extract_context(emu, op)

            # only extract once at tightloop end
            self.tloop_endvas.remove(endpc)


def extract_tightstring_contexts(vw, fva, tloops):
    emu = floss.utils.make_emulator(vw)
    monitor = TightstringContextMonitor(vw, emu.getStackCounter(), tloops)
    driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)
    driver.add_monitor(monitor)
    driver.runFunction(fva, maxhit=0x100, maxrep=0x100, func_only=True)
    return monitor.ctxs, monitor.pre_ctx_strings


def extract_tightstrings(vw, tightloop_functions, quiet=False):
    """
    Extracts tightstrings from functions that contain tight loops.
    Tightstrings are a special form of stackstrings. Their bytes are loaded on the stack and then modified in a
    tight loop. To extract tightstrings we use a mix between the string decoding and stackstring algorithms.

    To reduce computation time we only run this on previously identified functions that contain tight loops.

    :param vw: The vivisect workspace
    :param tightloop_functions: functions containing tight loops
    :param quiet: do NOT show progress bar
    :rtype: Generator[StackString]
    """
    # TODO add test sample(s) and tests
    pbar = tqdm.tqdm
    if quiet:
        # do not use tqdm to avoid unnecessary side effects when caller intends
        # to disable progress completely
        pbar = lambda s, *args, **kwargs: s

    pb = pbar(tightloop_functions.items(), desc="extracting tightstrings", unit=" functions")
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva, tloops in pb:
            fva_s = f"0x{fva:x}"
            pb.set_description(f"extracting tightstrings from {fva_s}")
            with floss.utils.timing(fva_s):
                logger.debug("extracting tightstrings from function: 0x%x", fva)
                ctxs, pre_ctx_strings = extract_tightstring_contexts(vw, fva, tloops)
                logger.trace("pre_ctx strings: %s", pre_ctx_strings)
                for ctx in ctxs:
                    logger.trace(
                        "extracting tightstring at checkpoint: 0x%x stacksize: 0x%x", ctx.pc, ctx.init_sp - ctx.sp
                    )
                    for s in chain(
                        floss.strings.extract_ascii_strings(ctx.stack_memory),
                        floss.strings.extract_unicode_strings(ctx.stack_memory),
                    ):

                        # TODO sanitize/cleanup string?
                        #  pVA and other prefixes
                        # if floss.utils.is_fp_string(s.string):
                        #     continue
                        # stripped_string = floss.utils.strip_string(s.string)

                        # TODO remove dups, e.g. in e5f5ad

                        if s.string not in pre_ctx_strings:
                            frame_offset = (ctx.init_sp - ctx.sp) - s.offset - stackstrings.getPointerSize(vw)
                            ts = TightString(
                                fva, s.string, s.encoding, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset
                            )
                            # TODO option/format to log quiet and regular, this is verbose output here currently
                            logger.info(
                                "%s [%s] in 0x%x at frame offset 0x%x", ts.string, ts.encoding, fva, ts.frame_offset
                            )
                            yield ts
