# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import contextlib
from collections import namedtuple

import envi
import viv_utils
import viv_utils.emulator_drivers

import floss.utils
import floss.api_hooks

# TODO get return address from emu_snap
FunctionContext = namedtuple("FunctionContext", ["emu_snap", "return_address", "decoded_at_va"])


class CallMonitor(viv_utils.emulator_drivers.Monitor):
    """collect call arguments to a target function during emulation"""

    def __init__(self, vivisect_workspace, target_fva):
        """:param target_fva: address of function whose arguments to monitor"""
        viv_utils.emulator_drivers.Monitor.__init__(self, vivisect_workspace)
        self.target_function_va = target_fva
        self.function_contexts = []

    def apicall(self, emu, op, pc, api, argv):
        return_address = self.getStackValue(emu, 0)
        if pc == self.target_function_va:
            self.function_contexts.append(FunctionContext(emu.getEmuSnap(), return_address, op.va))

    def get_contexts(self):
        return self.function_contexts

    def prehook(self, emu, op, starteip):
        self.d("%s: %s", hex(starteip), op)


@contextlib.contextmanager
def installed_monitor(driver, monitor):
    try:
        driver.add_monitor(monitor)
        yield
    finally:
        driver.remove_monitor(monitor)


class FunctionArgumentGetter(viv_utils.LoggingObject):
    def __init__(self, vivisect_workspace):
        viv_utils.LoggingObject.__init__(self)
        self.vivisect_workspace = vivisect_workspace
        self.emu = floss.utils.make_emulator(vivisect_workspace)
        self.driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(self.emu)
        self.index = viv_utils.InstructionFunctionIndex(vivisect_workspace)

    def get_all_function_contexts(self, function_va, max_hits):
        self.d("Getting function context for function at 0x%08X...", function_va)

        all_contexts = []
        for caller_va in self.get_caller_vas(function_va):
            function_context = self.get_contexts_via_monitor(caller_va, function_va, max_hits)
            all_contexts.extend(function_context)

        self.d("Got %d function contexts for function at 0x%08X.", len(all_contexts), function_va)
        return all_contexts

    def get_caller_vas(self, function_va):
        # optimization: avoid re-processing the same function repeatedly
        caller_function_vas = set([])
        for caller_va in self.vivisect_workspace.getCallers(function_va):
            self.d("    caller: %s" % hex(caller_va))

            try:
                op = self.vivisect_workspace.parseOpcode(caller_va)
            except Exception as e:
                self.d("      not a call instruction: failed to decode instruction: %s", e.message)
                continue

            if not (op.iflags & envi.IF_CALL):
                self.d("      not a call instruction: %s", op)
                continue

            try:
                # the address of the function that contains this instruction
                caller_function_va = self.index[caller_va]
            except KeyError:
                # there's a pointer outside a function, or
                # maybe two functions share the same basic block.
                # this is a limitation of viv_utils.FunctionIndex
                self.w("unknown caller function: 0x%x", caller_va)
                continue

            self.d("      function: %s", hex(caller_function_va))
            caller_function_vas.add(caller_function_va)
        return caller_function_vas

    def get_contexts_via_monitor(self, fva, target_fva, max_hits):
        """
        run the given function while collecting arguments to a target function
        """
        try:
            _ = self.index[fva]
        except KeyError:
            self.d("    unknown function")
            return []

        self.d("    emulating: %s, watching %s" % (hex(self.index[fva]), hex(target_fva)))
        monitor = CallMonitor(self.vivisect_workspace, target_fva)
        with installed_monitor(self.driver, monitor):
            with floss.api_hooks.defaultHooks(self.driver):
                self.driver.runFunction(self.index[fva], maxhit=max_hits, maxrep=0x1000, func_only=True)
        contexts = monitor.get_contexts()

        self.d("      results:")
        for c in contexts:
            self.d("        <context>")

        return contexts


def get_function_contexts(vw, fva, max_hits):
    return FunctionArgumentGetter(vw).get_all_function_contexts(fva, max_hits)
