"use strict";

const allowList = [
    "win32u!NtGdiCreateBitmap",
    "win32u!NtGdiCreateCompatibleDC",
    "win32u!NtGdiSelectBitmap",
    "win32u!NtGdiBitBlt",
    "win32u!NtGdiDeleteObjectApp"
];

function log(s) { host.diagnostics.debugLog(s + "\n"); }

function dumpRegisters(name) {
    const r = host.currentThread.Registers.User;
    log(JSON.stringify({
        syscall: name,
        rcx: r.rcx.toString(16),
        rdx: r.rdx.toString(16),
        r8: r.r8.toString(16),
        r9: r.r9.toString(16),
        rsp: r.rsp.toString(16)
    }));
}

function initializeScript() {
    log("syscall corpus collector skeleton loaded");
    for (const name of allowList) log("allow: " + name);
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(function(){ dumpRegisters("manual"); }, "dumpSyscallArgs")
    ];
}

// Next step: resolve symbols, install code breakpoints, read stack arguments at
// RSP+0x28 onward, and install temporary return breakpoints for outputs.
