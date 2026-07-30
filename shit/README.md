# NtGdi kAFL userspace harness

Keep `generated_ntgdi_harness.cpp` beside `main.cpp`. The generated file is
included directly so its translation-unit-local export table, scratch arena,
and handle pools can be initialized by `main.cpp`.

Build from Linux:

```bash
./build.sh
```

`KAFL_INCLUDE` only matters if you need extra kAFL headers beyond
`nyx_api.h` (already vendored in this directory, see below); it defaults to
`../` and is otherwise unused.

This produces two executables in `build/`:

- `ntgdi_fuzzer.exe` — the actual kAFL/Nyx agent. Runs inside the QEMU-Nyx
  VM under the fuzzer.
- `ntgdi_repro.exe` — same dispatcher/decoder code, built with
  `-DKAFL_REPRO_MODE`, but with every kAFL hypercall compiled out (see
  `#ifdef KAFL_REPRO_MODE` in `main.cpp`). Replays one saved testcase file
  through `DispatchGeneratedNtGdi()` outside of kAFL entirely, so a crash
  found while fuzzing can be reproduced/debugged (e.g. under WinDbg) without
  the VM or hypervisor:
  ```
  ntgdi_repro.exe path\to\testcase.bin
  ```
  It prints `[repro] CRASH: exception 0x... at 0x...` and exits non-zero on
  a crash, or `[+] Dispatch returned without crashing.` otherwise. Both
  binaries share all the harness setup code (`CreateHarnessResources`,
  `ResolveGeneratedExports`, `InitializeHandlePools`); only the kAFL
  protocol / IP-range / panic-hook code (`#ifndef KAFL_REPRO_MODE`-guarded)
  and the exception handler's response to a crash differ between them.

## Kernel coverage and crash classification

`win32u.dll` (which the harness calls into) is just a thin usermode
syscall-stub layer — the real `NtGdi*` implementation, and the bugs worth
finding, live in the kernel driver (`win32kbase.sys`/`win32kfull.sys`, with
`win32k.sys` itself reduced to a thin loader/shim on modern Windows). PT
IP-range filters don't care about ring 0 vs ring 3, they're just address
intervals, so kernel coverage requires explicitly submitting ranges that
cover those modules — it isn't automatic just because the harness triggers
kernel code via a syscall.

`main.cpp` submits all 4 available hardware IP-filter slots (Intel PT has
exactly 4, a CPU limit, not a kAFL one):

- index 0: the harness's own `.text` (`SubmitOwnCodeRange`)
- index 1-3: `win32kbase.sys`, `win32kfull.sys`, `win32k.sys`
  (`SubmitKernelCodeRanges`), resolved from usermode via
  `EnumDeviceDrivers`/`GetDeviceDriverBaseNameA` (same technique as the
  reference `driver/target.md` example) plus a `LoadLibraryExA(...,
  DONT_RESOLVE_DLL_REFERENCES)` of each module purely to read its `.text`
  section out of its own PE headers.

Deliberately not a single range spanning the whole address space: with
only 4 hardware slots total, an all-of-memory range would burn one of them
on a range that also includes every unrelated ntoskrnl subsystem, other
drivers, the scheduler, interrupts, etc — drowning the coverage bitmap in
noise unrelated to GDI and slowing down trace decode/exec throughput for no
benefit. Targeted beats broad here.

**Distinguishing usermode harness bugs from real kernel crashes:** the two
are now reported through different hypercalls, so they land in different
columns of kAFL's stats/GUI:

- A crash caught by the harness's own `AddVectoredExceptionHandler` (i.e. a
  usermode exception — most likely an out-of-bounds read/write in the
  generated decoder's input/output buffers, not a kernel bug) reports via
  `HYPERCALL_KAFL_KASAN`, which kAFL buckets under **AddSan**.
- A real kernel bugcheck reports via `HYPERCALL_KAFL_PANIC`, which kAFL
  buckets under **Crash** — but only because `SubmitKernelPanicHooks()`
  resolves `KeBugCheck`/`KeBugCheckEx` in `ntoskrnl.exe` (same
  `resolve_KeBugCheck()` technique as `driver/target.md`) and registers them
  via `HYPERCALL_KAFL_SUBMIT_PANIC`, so QEMU rewrites their entry points to
  emit a PANIC hypercall before the kernel finishes bugchecking. Without
  this, a real win32k memory-corruption bug would just hang the guest until
  the fuzzer's timeout detector kills it, and show up as a **Timeout**
  finding instead of a **Crash**.

So: **AddSan** findings are almost certainly harness-side bugs you don't
care about; **Crash** findings are real kernel bugchecks; a burst of
**Timeout** findings after these changes may be kernel crashes that
`SubmitKernelPanicHooks()` failed to hook (check the harness's `hprintf`
log for its `[-] WARNING` lines around `ntoskrnl.exe`/module resolution).

Important:

- Use `x86_64-w64-mingw32-g++`, not `gcc`; this is C++17 code.
- `hprintf` comes from `nyx_api.h` (vendored locally), not `kafl_user.h` —
  that header never existed in the real kAFL/kafl.targets project; it was a
  bad guess from an earlier debugging session. The real header ships from
  <https://github.com/IntelLabs/kafl.targets/blob/master/nyx_api.h> and is
  a single self-contained file (hypercall wrapper, `hprintf`/`habort`,
  `kAFL_payload`/`host_config_t`/`agent_config_t` structs).
- `ddk_headers/` vendors `winddi.h`, `d3dnthal.h`, `ntgdi.h`, `prntfont.h`,
  `ddrawint.h`, `d3dtypes.h`, `d3dcaps.h`-adjacent, `ddraw.h`, `dvp.h`, and
  `dxgiformat.h` — the same ReactOS-derived header set the type-graph parser
  (`../type_graph/headers`) used to generate `generated_ntgdi_harness.cpp`.
  These **must** come before MinGW's own system includes on the `-I` line:
  - MinGW's own `winddi.h` `#include`s `<d3dnthal.h>`, which MinGW does not
    ship at all — a straight build fails with
    `fatal error: d3dnthal.h: No such file or directory`.
  - MinGW's own `d3dtypes.h`/`d3dcaps.h` are the modern DirectX SDK
    versions and don't define the old D3D NT HAL structures
    (`D3DNTHAL_CALLBACKS`, etc.) that the generated decoder needs.
  - Mixing MinGW's `winddi.h`/`ntgdi.h`/`prntfont.h` with the vendored
    `d3dnthal.h` (or vice versa) risks silent struct-layout mismatches
    since they weren't generated as a matched set. `build.sh` puts
    `ddk_headers/` first on `-I` so the whole DDK-ish header set resolves
    consistently from one source.
- Do not compile `generated_ntgdi_harness.cpp` separately because `main.cpp`
  includes it.
- Keep the QEMU dirty-ring/Cirrus-VRAM compatibility patch already applied.
- Supply a seed corpus whose first two bytes are a little-endian syscall index.
