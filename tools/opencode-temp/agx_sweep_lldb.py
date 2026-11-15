#!/usr/bin/env python
"""LLDB driver: run the AGXG18P external-method argument-shape sweep inside
the already-installed, dev-signed AGXProbe app (no Mac / Xcode needed)."""
import lldb
import os
import time

PAYLOAD = os.environ.get("AGX_PAYLOAD", r"G:/REPO\tools\opencode-temp\agx_sweep_payload.c")


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f agx_sweep_lldb.agxsweep agxsweep")
    debugger.HandleCommand("command script add -f agx_sweep_lldb.agxwhere agxwhere")
    debugger.HandleCommand("command script add -f agx_sweep_lldb.agxrun agxrun")


def agxwhere(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    print("=== AGXWHERE ===")
    print("modules:", [m.file.fullpath for m in target.module_list()][:12])
    print("state:", process.GetState(), "pid:", process.GetProcessID())
    for t in process:
        print("  thread", t.GetThreadID(), t.GetName())
        f = t.GetSelectedFrame()
        if f:
            print("    frame:", f)


def agxrun(debugger, command, result, internal_dict):
    """Resume the target, let the app initialise, then stop it."""
    process = debugger.GetSelectedTarget().GetProcess()
    if process.GetState() == lldb.eStateStopped:
        print("AGXRUN: continuing...")
        process.Continue()
        time.sleep(5)
        print("AGXRUN: interrupting...")
        process.Stop()
        time.sleep(1.5)
    print("AGXRUN: state =", process.GetState())


def agxsweep(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if not process or not process.IsValid():
        print("AGXSWEEP: no process")
        return
    if process.GetState() != lldb.eStateStopped:
        print("AGXSWEEP: stopping process")
        process.Stop()
        time.sleep(1.5)

    with open(PAYLOAD, "r") as fh:
        expr = fh.read()

    opts = lldb.SBExpressionOptions()
    opts.SetLanguage(lldb.eLanguageTypeC)
    opts.SetTryAllThreads(True)
    opts.SetUnwindOnError(False)

    print("AGXSWEEP: evaluating payload (%d bytes)..." % len(expr))
    t0 = time.time()
    val = target.EvaluateExpression(expr, opts)
    err = val.GetError()
    if err.Fail():
        print("AGXSWEEP: expression error:", err.GetCString())
    else:
        print("AGXSWEEP: value =", val.GetSummary())
    print("AGXSWEEP: elapsed %.1fs" % (time.time() - t0))
