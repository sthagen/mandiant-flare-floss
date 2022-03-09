from typing import Set, List, Tuple

import tqdm
import viv_utils
import tqdm.contrib.logging

import floss.utils
import floss.features.features
from floss.utils import extract_strings
from floss.results import TightString
from floss.stackstrings import CallContext, EmptyContext, StackstringContextMonitor
from floss.render.default import Verbosity

logger = floss.logging.getLogger(__name__)


class TightstringContextMonitor(StackstringContextMonitor):
    def __init__(self, vw, sp, min_length, tloops):
        super(TightstringContextMonitor, self).__init__(vw, sp, [])
        self.min_length = min_length

        self.tloop_startvas = set([t.startva for t in tloops])
        self.tloop_endvas = set([t.endva for t in tloops])
        logger.trace(" stavas: %s", ", ".join(map(hex, sorted(self.tloop_startvas))))
        logger.trace(" endvas: %s", ", ".join(map(hex, sorted(self.tloop_endvas))))

        # store existing (FP) stackstrings before tightstring loop executes
        self.curr_pre_ctx_strings = set()

    def apicall(self, emu, op, pc, api, argv):
        pass

    def prehook(self, emu, op, startpc):
        if startpc in self.tloop_startvas:
            try:
                stack_buf = self.get_call_context(emu, op).stack_memory
            except ValueError as e:
                logger.debug("%s", e)
                return
            except EmptyContext:
                pass
            else:
                # track strings present before emulating tight loop
                self.curr_pre_ctx_strings.update(
                    list(map(lambda s: s.string, extract_strings(stack_buf, self.min_length)))
                )

            # only save one context per tightloop
            self.tloop_startvas.remove(startpc)

    def posthook(self, emu, op, endpc):
        if endpc in self.tloop_endvas:
            logger.trace("extracting context at endpc: 0x%x", endpc)
            self.extract_context(emu, op)

            # only extract once at tightloop end
            self.tloop_endvas.remove(endpc)


def extract_tightstring_contexts(vw, fva, min_length, tloops) -> List[CallContext]:
    emu = floss.utils.make_emulator(vw)
    monitor = TightstringContextMonitor(vw, emu.getStackCounter(), min_length, tloops)
    driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)
    driver.add_monitor(monitor)
    driver.runFunction(fva, maxhit=0x100, maxrep=0x100, func_only=True)
    return monitor.ctxs


def extract_tightstrings(
    vw, tightloop_functions, min_length, verbosity=Verbosity.DEFAULT, disable_progress=False
) -> List[TightString]:
    """
    Extracts tightstrings from functions that contain tight loops.
    Tightstrings are a special form of stackstrings. Their bytes are loaded on the stack and then modified in a
    tight loop. To extract tightstrings we use a mix between the string decoding and stackstring algorithms.

    To reduce computation time we only run this on previously identified functions that contain tight loops.

    :param vw: The vivisect workspace
    :param tightloop_functions: functions containing tight loops
    :param min_length: minimum string length
    :param verbosity: verbosity level
    :param disable_progress: do NOT show progress bar
    """
    logger.info("extracting tightstrings from %d functions...", len(tightloop_functions))

    tight_strings = list()
    # TODO add test sample(s) and tests
    # works but slow: 6c6a2bfa5846fab374b2b97e65095ec9
    # slow: 3176c4a2755ae00f4fffe079608c7b25 (no TS?)
    pb = floss.utils.get_progress_bar(
        tightloop_functions.items(), disable_progress, desc="extracting tightstrings", unit=" functions"
    )
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva, tloops in pb:
            with floss.utils.timing(f"0x{fva:x}"):
                logger.debug("extracting tightstrings from function 0x%x", fva)
                if isinstance(pb, tqdm.tqdm):
                    pb.set_description(f"extracting tightstrings from function 0x{fva:x}")

                ctxs = extract_tightstring_contexts(vw, fva, min_length, tloops)
                for n, ctx in enumerate(ctxs, 1):
                    logger.trace(
                        "extracting tightstring at checkpoint: 0x%x stacksize: 0x%x", ctx.pc, ctx.init_sp - ctx.sp
                    )
                    logger.trace("pre_ctx strings: %s", ctx.pre_ctx_strings)
                    for s in extract_strings(ctx.stack_memory, min_length, exclude=ctx.pre_ctx_strings):
                        frame_offset = (ctx.init_sp - ctx.sp) - s.offset - floss.utils.getPointerSize(vw)
                        ts = TightString(fva, s.string, s.encoding, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset)
                        floss.results.log_result(ts, verbosity)
                        # TODO add ts to exclude set?
                        tight_strings.append(ts)
    return tight_strings
