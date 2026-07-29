# NtGdi kAFL userspace harness

Keep `generated_ntgdi_harness.cpp` beside `main.cpp`. The generated file is
included directly so its translation-unit-local export table, scratch arena,
and handle pools can be initialized by `main.cpp`.

Build from Linux:

```bash
KAFL_INCLUDE=/path/to/kafl/include ./build.sh
```

For the existing `examples/windows_x86_64/src/userspace` layout, copy these two
source files there and use:

```bash
KAFL_INCLUDE=../ ./build.sh
```

The executable is written to `build/ntgdi_fuzzer.exe`.

Important:

- Use `x86_64-w64-mingw32-g++`, not `gcc`; this is C++17 code.
- `hprintf` comes from `kafl_user.h`; it is not an MSVC function.
- Do not compile `generated_ntgdi_harness.cpp` separately because `main.cpp`
  includes it.
- Keep the QEMU dirty-ring/Cirrus-VRAM compatibility patch already applied.
- Supply a seed corpus whose first two bytes are a little-endian syscall index.
