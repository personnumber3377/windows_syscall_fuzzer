# Windows system call fuzzer

Visual Studio 2022 C++20 starter for resource-aware Windows fuzzing.

The runtime pools contain valid HDC, HBITMAP, HBRUSH, HPEN, HRGN, file, event,
and file-mapping handles. Serialized input stores indices, never raw Windows
handle values. `index % pool.size()` selects a live object.

Open `win_resource_fuzzer.sln`, build x64, and run:

    win_resource_fuzzer.exe corpus\\seed.bin

`WtfAdapterExample.cpp` shows the intended split: initialize resources before the
snapshot, then call the unchanged runner with WTF's testcase pointer and length.
It is intentionally excluded from the default project until adapted to your WTF
interfaces.
