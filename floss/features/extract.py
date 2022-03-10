import envi
import networkx
import vivisect
import viv_utils
from networkx import strongly_connected_components
from envi.archs.i386.opconst import INS_MOV, INS_ROL, INS_ROR, INS_SHL, INS_SHR, INS_XOR

import floss.logging_
from floss.features.features import (
    Mov,
    Loop,
    Nzxor,
    Shift,
    CallsTo,
    NzxorLoop,
    TightLoop,
    KindaTightLoop,
    NzxorTightLoop,
)

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40

SHIFT_ROTATE_INS = (INS_SHL, INS_SHR, INS_ROL, INS_ROR)

logger = floss.logging_.getLogger(__name__)


def extract_insn_nzxor(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    if insn.opcode != INS_XOR:
        return

    if insn.opers[0] == insn.opers[1]:
        return

    if is_security_cookie(f, bb, insn):
        return

    yield Nzxor(insn)


def is_security_cookie(f, bb, insn) -> bool:
    """
    check if an instruction is related to security cookie checks
    """
    # security cookie check should use SP or BP
    oper = insn.opers[1]
    if oper.isReg() and oper.reg not in [
        envi.archs.i386.regs.REG_ESP,
        envi.archs.i386.regs.REG_EBP,
        # TODO: do x64 support for real.
        envi.archs.amd64.regs.REG_RBP,
        envi.archs.amd64.regs.REG_RSP,
    ]:
        return False

    # expect security cookie init in first basic block within first bytes (instructions)
    bb0 = f.basic_blocks[0]

    if bb == bb0 and insn.va < (bb.va + SECURITY_COOKIE_BYTES_DELTA):
        return True

    # ... or within last bytes (instructions) before a return
    elif bb.instructions[-1].isReturn() and insn.va > (bb.va + bb.size - SECURITY_COOKIE_BYTES_DELTA):
        return True

    return False


def extract_insn_shift(f, bb, insn):
    if insn.opcode in SHIFT_ROTATE_INS:
        yield Shift(insn)


def extract_insn_mov(f, bb, insn):
    # identify register dereferenced writes to memory
    #   mov byte  [eax], cl
    #   mov dword [edx], eax

    if insn.opcode == INS_MOV:
        # don't handle len(ops) == 0 for `rep movsb` etc. often used for memcpy
        if len(insn.opers) != 2:
            return

        op0, op1 = insn.opers

        if not op0.isDeref():
            return

        if op1.isImmed():
            return

        # as an additional heuristic for global string decoding instructions like
        #   mov     dword_40400C, 0
        # could be captured via envi.archs.i386.disasm.i386ImmMemOper
        #
        # i386RegMemOper could also capture operands with displacement != 0
        #   mov     [edx+4], eax

        if isinstance(op0, envi.archs.i386.disasm.i386RegMemOper):
            if op0.disp == 0:
                yield Mov(insn)


def extract_function_calls_to(f):
    yield CallsTo(f.vw, [x[0] for x in f.vw.getXrefsTo(f.va, rtype=vivisect.const.REF_CODE)])


def extract_function_kinda_tight_loop(f):
    """
    Yields tight loop features in the provided function
    Algorithm by Blaine S.
    """
    cfg = viv_utils.CFG(f)

    try:
        root_bb_va = cfg.get_root_basic_block().va
    except KeyError:
        # TODO fix in viv-utils
        # likely wrongly identified or analyzed function
        return
    leaf_bb_vas = {bb.va for bb in cfg.get_leaf_basic_blocks()}

    for bb in f.basic_blocks:
        # skip first and last BBs
        if bb.va == root_bb_va:
            continue

        if bb.va in leaf_bb_vas:
            continue

        succs = tuple(cfg.get_successor_basic_blocks(bb))

        # we're looking for one of two cases:
        #
        # A) block conditionally loops to itself:
        #
        #         |
        #         v v--+
        #       [ a ]  |
        #       /   \--+
        #    [ b ]
        #
        # path: [a]->[a]
        #
        #
        # B) block conditionally branches to block that loops to itself:
        #
        #
        #         |
        #         v v----+
        #       [ a ]    |
        #       /   \    |
        #    [ b ] [ c ] |
        #             \--+
        #
        # path: [a]->[c]->[a]

        # skip blocks that don't have exactly 2 successors
        if len(succs) != 2:
            continue

        # the BB that branches back to `bb`, either [a] or [c]
        # or None if a tight loop is not found.
        loop_bb = None

        # find very tight loops: [a]->[a]
        for suc in succs:
            if suc.va == bb.va:
                loop_bb = bb

        # find semi tight loops: [a]->[c]->[a]
        if not loop_bb:
            for suc in succs:
                suc_succs = [x for x in cfg.get_successor_basic_blocks(suc)]
                if len(suc_succs) != 1:
                    continue
                if suc_succs[0] != bb.va:
                    continue

                loop_bb = suc_succs[0]
                break

        if not loop_bb:
            continue

        # get the block after loop, [b]
        next_bb = None
        for suc in succs:
            if loop_bb.va != suc.va:
                next_bb = suc
                break

        if not next_bb:
            continue

        # Blaine's algorithm gets the block before the loop here
        # additionally, he prunes the identified loops before processing further
        # TODO prune loops that do not write memory

        yield KindaTightLoop(bb.va, next_bb.va)


def extract_bb_tight_loop(f, bb):
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(f, bb):
        yield TightLoop(bb.va, bb.va + bb.size)


def _bb_has_tight_loop(f, bb):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    if len(bb.instructions) > 0:
        for bva, bflags in bb.instructions[-1].getBranches():
            if bflags & envi.BR_COND:
                if bva == bb.va:
                    return True
    return False


def abstract_nzxor_tightloop(features):
    for tl in filter(lambda f: isinstance(f, TightLoop), features):
        for nzxor in filter(lambda f: isinstance(f, Nzxor), features):
            if tl.startva <= nzxor.insn.va <= tl.endva:
                yield NzxorTightLoop()


def abstract_nzxor_loop(features):
    if any(isinstance(f, Nzxor) for f in features) and any(isinstance(f, Loop) for f in features):
        yield NzxorLoop()


def extract_function_loop(f):
    """
    parse if a function has a loop
    """
    edges = []

    for bb in f.basic_blocks:
        if len(bb.instructions) > 0:
            for bva, bflags in bb.instructions[-1].getBranches():
                # vivisect does not set branch flags for non-conditional jmp so add explicit check
                if (
                    bflags & envi.BR_COND
                    or bflags & envi.BR_FALL
                    or bflags & envi.BR_TABLE
                    or bb.instructions[-1].mnem == "jmp"
                ):
                    edges.append((bb.va, bva))

    g = networkx.DiGraph()
    g.add_edges_from(edges)
    comps = strongly_connected_components(g)
    for comp in comps:
        if len(comp) >= 2:
            # TODO get list of bb start/end eas
            yield Loop(comp)


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_loop,
    extract_function_kinda_tight_loop,
    # extract_function_order,  # TODO decoding functions are often one of the first in a program
    # extract_num_api_calls,  # TODO decoding functions don't normally contain many (API) calls
)


def extract_function_features(f):
    for func_handler in FUNCTION_HANDLERS:
        for feature in func_handler(f):
            yield feature


BASIC_BLOCK_HANDLERS = (extract_bb_tight_loop,)


def extract_basic_block_features(f, bb):
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature in bb_handler(f, bb):
            yield feature


INSTRUCTION_HANDLERS = (
    extract_insn_nzxor,
    extract_insn_shift,
    extract_insn_mov,
)


def extract_insn_features(f, bb, insn):
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature in insn_handler(f, bb, insn):
            yield feature


ABSTRACTION_HANDLERS = (
    abstract_nzxor_loop,
    abstract_nzxor_tightloop,
)


def abstract_features(features):
    for abst_handler in ABSTRACTION_HANDLERS:
        for feature in abst_handler(features):
            yield feature
