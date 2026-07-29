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

The executable is written to `build/ntgdi_fuzzer.exe`.

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
