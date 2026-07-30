#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wingdi.h>
#include <psapi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "nyx_api.h"
}

// nyx_api.h's __MINGW64__ branch exists for an old MinGW without a real
// <stdint.h> and unconditionally #defines uint8_t/uint32_t/uint64_t/
// int32_t/u_long to the UINTn/INTn Windows types -- but modern mingw-w64
// still defines __MINGW64__, so this fires here too, on top of the real
// <cstdint> typedefs already included above. Left alone, it silently
// mangles any *qualified* use later in this file (std::uint8_t becomes the
// nonexistent std::UINT8) while plain uint8_t keeps compiling by accident.
// nyx_api.h itself is already done using these macros by this point, so
// it's safe to drop them and let the token mean the real typedef again.
#ifdef __MINGW64__
#undef uint64_t
#undef int32_t
#undef uint32_t
#undef u_long
#undef uint8_t
#endif

// KAFL_REPRO_MODE builds run standalone on real Windows (no Nyx hypervisor
// underneath), so they must never execute a kAFL hypercall (vmcall) --
// hprintf/habort do exactly that and would fault immediately. Route all
// logging/abort call sites through these macros instead of calling
// hprintf/habort directly, so the same source compiles into either binary.
#ifdef KAFL_REPRO_MODE
#define HLOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)
[[noreturn]] inline void ReproAbort(const char* msg) {
    fprintf(stderr, "[repro] ABORT: %s", msg);
    fflush(stderr);
    ExitProcess(1);
}
#define HABORT(msg) ReproAbort(msg)
#else
#define HLOG(...) hprintf(__VA_ARGS__)
#define HABORT(msg) habort(msg)
#endif

// The generated file intentionally stays in this translation unit because its
// handle pools and export table have internal linkage.
#include "generated_ntgdi_harness.cpp"

namespace {

struct HarnessResources {
    HWND desktop_window = nullptr;
    HDC screen_dc = nullptr;
    HDC memory_dc = nullptr;
    HBITMAP bitmap = nullptr;
    HGDIOBJ old_bitmap = nullptr;
    HBRUSH solid_brush = nullptr;
    HBRUSH hatch_brush = nullptr;
    HPEN pen = nullptr;
    HFONT font = nullptr;
    HRGN region = nullptr;
    HPALETTE palette = nullptr;
    HANDLE event_handle = nullptr;
};

HarnessResources g_resources;
PVOID g_vectored_handler = nullptr;

#ifdef KAFL_REPRO_MODE

// No hypervisor underneath in repro builds: report the crash on stdio and
// terminate instead of issuing a kAFL hypercall.
LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS* info) noexcept {
    const DWORD code = info && info->ExceptionRecord
        ? info->ExceptionRecord->ExceptionCode
        : 0;
    const void* address = info && info->ExceptionRecord
        ? info->ExceptionRecord->ExceptionAddress
        : nullptr;

    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case STATUS_STACK_BUFFER_OVERRUN:
    case STATUS_FATAL_APP_EXIT:
    case 0xC0000374u: // STATUS_HEAP_CORRUPTION
        fprintf(stderr, "[repro] CRASH: exception 0x%08lX at %p\n",
                code, address);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), code);
        for (;;) {} // TerminateProcess does not return
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

#else

// Reached only through our own VEH below, i.e. a usermode exception inside
// the harness/dispatcher/decoder itself (an out-of-bounds read/write on the
// generated input/output buffers, a bad handle dereference, etc). This is a
// harness-side bug, not a target (kernel) crash -- the target is win32k, not
// this harness -- so by design it is NOT reported to kAFL as any kind of
// finding. It calls RELEASE, the same hypercall a normal non-crashing
// execution ends with, so kAFL logs it as a completely unremarkable
// "regular" execution: no corpus entry, no stats bump, nothing to triage.
// RELEASE triggers the same automatic Nyx snapshot restore that PANIC/KASAN
// do, and (like kAFL_hypercall itself) doesn't care what called it or what
// state the stack is in, so it's safe to call directly from the VEH just
// like KaflPanic-style handlers do.
//
// Only a real win32k/ntoskrnl bugcheck -- caught via the SUBMIT_PANIC hooks
// in SubmitKernelPanicHooks() below, which is a completely separate code
// path that never goes through this VEH at all -- produces a "Crash"
// finding now. If you ever want harness-side bugs visible again (e.g. to
// go fix them because they might be masking deeper kernel paths), swap
// HYPERCALL_KAFL_RELEASE below back to HYPERCALL_KAFL_KASAN.
[[noreturn]] void RecoverFromHarnessFault(std::uintptr_t code) noexcept {
    HLOG("[-] Discarding usermode harness fault 0x%08llX (not reported to kAFL)\n",
         static_cast<unsigned long long>(code));
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    for (;;) {
        YieldProcessor();
    }
}

LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS* info) noexcept {
    const DWORD code = info && info->ExceptionRecord
        ? info->ExceptionRecord->ExceptionCode
        : 0;

    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case STATUS_STACK_BUFFER_OVERRUN:
    case STATUS_FATAL_APP_EXIT:
    case 0xC0000374u: // STATUS_HEAP_CORRUPTION
        RecoverFromHarnessFault(static_cast<std::uintptr_t>(code));
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

#endif // KAFL_REPRO_MODE

template <typename T>
void AddIfNonNull(std::vector<T>& pool, T value) {
    if (value != nullptr) {
        pool.push_back(value);
    }
}

template <typename T>
void AddNullFallback(std::vector<T>& pool) {
    if (pool.empty()) {
        pool.push_back(T{});
    }
}

bool CreatePaletteResource() {
    struct PaletteStorage {
        LOGPALETTE header;
        PALETTEENTRY extra_entries[3];
    } storage{};

    storage.header.palVersion = 0x300;
    storage.header.palNumEntries = 4;
    storage.header.palPalEntry[0] = {0x00, 0x00, 0x00, 0};
    storage.extra_entries[0] = {0xff, 0x00, 0x00, 0};
    storage.extra_entries[1] = {0x00, 0xff, 0x00, 0};
    storage.extra_entries[2] = {0x00, 0x00, 0xff, 0};

    g_resources.palette =
        CreatePalette(reinterpret_cast<const LOGPALETTE*>(&storage));
    return g_resources.palette != nullptr;
}

bool CreateHarnessResources() {
    g_resources.desktop_window = GetDesktopWindow();
    g_resources.screen_dc = GetDC(nullptr);
    if (!g_resources.screen_dc) {
        HLOG("[-] GetDC(NULL) failed: %lu\n", GetLastError());
        return false;
    }

    g_resources.memory_dc = CreateCompatibleDC(g_resources.screen_dc);
    if (!g_resources.memory_dc) {
        HLOG("[-] CreateCompatibleDC failed: %lu\n", GetLastError());
        return false;
    }

    g_resources.bitmap =
        CreateCompatibleBitmap(g_resources.screen_dc, 256, 256);
    if (!g_resources.bitmap) {
        HLOG("[-] CreateCompatibleBitmap failed: %lu\n", GetLastError());
        return false;
    }

    g_resources.old_bitmap =
        SelectObject(g_resources.memory_dc, g_resources.bitmap);
    g_resources.solid_brush = CreateSolidBrush(RGB(0x40, 0x80, 0xc0));
    g_resources.hatch_brush =
        CreateHatchBrush(HS_DIAGCROSS, RGB(0xc0, 0x40, 0x80));
    g_resources.pen = CreatePen(PS_SOLID, 1, RGB(0x20, 0xe0, 0x70));
    g_resources.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    g_resources.region = CreateRectRgn(0, 0, 128, 128);
    g_resources.event_handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CreatePaletteResource();

    // Force common user32/gdi32 lazy initialization before the snapshot.
    SelectObject(g_resources.memory_dc, g_resources.solid_brush);
    SelectObject(g_resources.memory_dc, g_resources.pen);
    SelectObject(g_resources.memory_dc, g_resources.font);
    SetBkMode(g_resources.memory_dc, TRANSPARENT);
    Rectangle(g_resources.memory_dc, 0, 0, 32, 32);
    GdiFlush();
    return true;
}

void DestroyHarnessResources() {
    if (g_resources.memory_dc && g_resources.old_bitmap &&
        g_resources.old_bitmap != HGDI_ERROR) {
        SelectObject(g_resources.memory_dc, g_resources.old_bitmap);
    }
    if (g_resources.region) DeleteObject(g_resources.region);
    if (g_resources.pen) DeleteObject(g_resources.pen);
    if (g_resources.solid_brush) DeleteObject(g_resources.solid_brush);
    if (g_resources.hatch_brush) DeleteObject(g_resources.hatch_brush);
    if (g_resources.palette) DeleteObject(g_resources.palette);
    if (g_resources.bitmap) DeleteObject(g_resources.bitmap);
    if (g_resources.memory_dc) DeleteDC(g_resources.memory_dc);
    if (g_resources.screen_dc) ReleaseDC(nullptr, g_resources.screen_dc);
    if (g_resources.event_handle) CloseHandle(g_resources.event_handle);
    g_resources = {};
}

bool ResolveGeneratedExports() {
    // LoadLibrary is deliberate: it guarantees both modules are initialized
    // before the snapshot instead of relying on incidental imports.
    HMODULE win32u = LoadLibraryW(L"win32u.dll");
    HMODULE gdi32 = LoadLibraryW(L"gdi32.dll");
    if (!win32u && !gdi32) {
        return false;
    }

    std::size_t resolved = 0;
    for (std::size_t i = 0; i < g_generated_ntgdi_export_count; ++i) {
        GeneratedNtGdiExport& entry = g_generated_ntgdi_exports[i];
        FARPROC address = win32u ? GetProcAddress(win32u, entry.name) : nullptr;
        if (!address && gdi32) {
            address = GetProcAddress(gdi32, entry.name);
        }
        entry.address = address;
        resolved += address != nullptr;
    }

    HLOG("[+] Resolved %llu/%llu generated exports\n",
         static_cast<unsigned long long>(resolved),
         static_cast<unsigned long long>(g_generated_ntgdi_export_count));
    return resolved != 0;
}

bool InitializeHandlePools() {
    g_handles_DHPDEV.clear();
    g_handles_DHSURF.clear();
    g_handles_HANDLE.clear();
    g_handles_HBITMAP.clear();
    g_handles_HBRUSH.clear();
    g_handles_HCOLORSPACE.clear();
    g_handles_HDC.clear();
    g_handles_HDEV.clear();
    g_handles_HFONT.clear();
    g_handles_HGLYPH.clear();
    g_handles_HLSURF.clear();
    g_handles_HPALETTE.clear();
    g_handles_HPEN.clear();
    g_handles_HRESULT.clear();
    g_handles_HRGN.clear();
    g_handles_HSURF.clear();
    g_handles_HUMPD.clear();
    g_handles_HWND.clear();

    AddIfNonNull(g_handles_HDC, g_resources.screen_dc);
    AddIfNonNull(g_handles_HDC, g_resources.memory_dc);
    AddIfNonNull(g_handles_HBITMAP, g_resources.bitmap);
    AddIfNonNull(g_handles_HBRUSH, g_resources.solid_brush);
    AddIfNonNull(g_handles_HBRUSH, g_resources.hatch_brush);
    AddIfNonNull(g_handles_HBRUSH,
                 static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH)));
    AddIfNonNull(g_handles_HBRUSH,
                 static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    AddIfNonNull(g_handles_HPEN, g_resources.pen);
    AddIfNonNull(g_handles_HPEN,
                 static_cast<HPEN>(GetStockObject(BLACK_PEN)));
    AddIfNonNull(g_handles_HFONT, g_resources.font);
    AddIfNonNull(g_handles_HFONT,
                 static_cast<HFONT>(GetStockObject(SYSTEM_FONT)));
    AddIfNonNull(g_handles_HRGN, g_resources.region);
    AddIfNonNull(g_handles_HPALETTE, g_resources.palette);
    AddIfNonNull(g_handles_HWND, g_resources.desktop_window);
    AddIfNonNull(g_handles_HANDLE, g_resources.event_handle);

    g_handles_HRESULT.push_back(S_OK);
    g_handles_HRESULT.push_back(E_FAIL);
    g_handles_HRESULT.push_back(E_INVALIDARG);
    g_handles_HGLYPH.push_back(static_cast<HGLYPH>(0));

    AddNullFallback(g_handles_DHPDEV);
    AddNullFallback(g_handles_DHSURF);
    AddNullFallback(g_handles_HCOLORSPACE);
    AddNullFallback(g_handles_HDEV);
    AddNullFallback(g_handles_HLSURF);
    AddNullFallback(g_handles_HSURF);
    AddNullFallback(g_handles_HUMPD);
    AddNullFallback(g_handles_HANDLE);
    AddNullFallback(g_handles_HBITMAP);
    AddNullFallback(g_handles_HBRUSH);
    AddNullFallback(g_handles_HDC);
    AddNullFallback(g_handles_HFONT);
    AddNullFallback(g_handles_HPALETTE);
    AddNullFallback(g_handles_HPEN);
    AddNullFallback(g_handles_HRGN);
    AddNullFallback(g_handles_HWND);
    return true;
}

// ---------------------------------------------------------------------
// Everything below this point issues kAFL hypercalls and only belongs in
// the fuzzing binary; KAFL_REPRO_MODE builds never link it in, so there is
// no way for the repro binary to accidentally execute a vmcall.
// ---------------------------------------------------------------------
#ifndef KAFL_REPRO_MODE

void SubmitInstrumentationRanges() {
    auto* ranges = static_cast<kAFL_ranges*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!ranges) {
        HLOG("[-] Cannot allocate kAFL range buffer: %lu\n", GetLastError());
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
        return;
    }

    std::memset(ranges, 0xff, 0x1000);
    HLOG("[+] range buffer %p...\n", ranges);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE,
                   reinterpret_cast<UINT64>(ranges));
}

// VirtualLock only succeeds for as many pages as fit in the process's
// current working-set quota (by default a few hundred KB, shared across
// every VirtualLock call the process makes). Grow it up front so locking
// the payload buffer and the .text section below don't run out of budget.
bool GrowWorkingSetQuota(SIZE_T extra_bytes) {
    SIZE_T min_ws = 0, max_ws = 0;
    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws)) {
        HLOG("[-] GetProcessWorkingSetSize failed: %lu\n", GetLastError());
        return false;
    }

    const SIZE_T slack = 4 * 1024 * 1024;
    const SIZE_T new_min = min_ws + extra_bytes + slack;
    const SIZE_T new_max = max_ws + extra_bytes + slack * 2;
    if (!SetProcessWorkingSetSize(GetCurrentProcess(), new_min, new_max)) {
        HLOG("[-] SetProcessWorkingSetSize(%zu, %zu) failed: %lu\n",
             new_min, new_max, GetLastError());
        return false;
    }
    return true;
}

// Parses the .text section (VirtualAddress/VirtualSize, i.e. RVAs) out of
// an already-mapped PE image (own process image, or a system module loaded
// solely to inspect its headers -- see LoadHeadersOnly() below).
bool GetTextSectionRva(HMODULE module, DWORD_PTR& rva, DWORD_PTR& size) {
    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(module) + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    auto* section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<PBYTE>(nt_headers) + sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = &section_headers[i];
        if (std::memcmp(section->Name, ".text", 5) != 0) {
            continue;
        }
        rva = section->VirtualAddress;
        size = section->Misc.VirtualSize;
        return true;
    }
    return false;
}

// Mirrors toyharness/toy.cpp's submit_ip_ranges(): tell the hypervisor about
// this executable's own .text section (IP filter index 0) so PT tracing
// covers the harness/dispatcher code, and pin those pages resident for
// libxdc.
//
// Locking .text is a best-effort prefetch hint, not a correctness
// requirement: QEMU-Nyx can dump code pages for the PT decoder even if
// they weren't resident at snapshot time (see USER_RANGE_ADVISE in
// hypercall_api.md), so a lock failure here must not abort the agent.
void SubmitOwnCodeRange() {
    HMODULE module = GetModuleHandleW(nullptr);
    if (!module) {
        HABORT("Cannot get module handle\n");
    }

    DWORD_PTR rva = 0, size = 0;
    if (!GetTextSectionRva(module, rva, size)) {
        HABORT("Couldn't locate .text section in own PE image\n");
    }

    const DWORD_PTR code_start = reinterpret_cast<DWORD_PTR>(module) + rva;
    const DWORD_PTR code_end = code_start + size;

    UINT64 buffer[3] = {0};
    buffer[0] = code_start; // low range
    buffer[1] = code_end;   // high range
    buffer[2] = 0;          // IP filter index 0: harness/dispatcher code
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, reinterpret_cast<UINT64>(buffer));

    GrowWorkingSetQuota(size);
    if (!VirtualLock(reinterpret_cast<LPVOID>(code_start), size)) {
        HLOG("[-] WARNING: Failed to lock own .text section resident: %lu\n",
             GetLastError());
    }
}

// EnumDeviceDrivers()/GetDeviceDriverBaseNameA() below only return real
// (non-zeroed) kernel addresses to callers holding SeDebugPrivilege --
// otherwise Windows treats it as a KASLR leak and returns garbage. Even on
// an Administrator token, that privilege exists but is *disabled* by
// default and has to be explicitly turned on; this is normally a silent
// failure (everything "succeeds", the addresses are just useless), so call
// this once before any kernel module resolution rather than hoping the
// account this harness runs under already has it enabled.
bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        HLOG("[-] WARNING: OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        HLOG("[-] WARNING: LookupPrivilegeValue(SeDebugPrivilege) failed: %lu\n",
             GetLastError());
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const BOOL adjusted = AdjustTokenPrivileges(
        token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const DWORD adjust_error = GetLastError();
    CloseHandle(token);

    if (!adjusted || adjust_error == ERROR_NOT_ALL_ASSIGNED) {
        HLOG("[-] WARNING: Could not enable SeDebugPrivilege (%lu) -- kernel "
             "module base addresses may resolve to garbage/zero. Run this "
             "harness as Administrator.\n", adjust_error);
        return false;
    }
    return true;
}

// Finds a currently-loaded KERNEL driver/module by (case-insensitive) base
// file name, using the same EnumDeviceDrivers()/GetDeviceDriverBaseNameA()
// technique the reference driver/vuln_test.c harness uses to locate its
// target .sys and ntoskrnl.exe from usermode (see driver/target.md, "Set IP
// ranges"). Returns the module's real kernel-mode base address. Call
// EnableDebugPrivilege() first (see above) or this will silently return
// zeroed/bogus addresses.
bool FindKernelModuleBase(const char* target_base_name, DWORD_PTR& kernel_base) {
    DWORD needed = 0;
    EnumDeviceDrivers(nullptr, 0, &needed);
    if (needed == 0) {
        return false;
    }

    std::vector<LPVOID> drivers(needed / sizeof(LPVOID));
    DWORD actually_needed = 0;
    if (!EnumDeviceDrivers(drivers.data(),
                            static_cast<DWORD>(drivers.size() * sizeof(LPVOID)),
                            &actually_needed)) {
        return false;
    }
    const std::size_t count =
        (std::min)(drivers.size(), actually_needed / sizeof(LPVOID));

    char name[MAX_PATH];
    for (std::size_t i = 0; i < count; ++i) {
        if (!GetDeviceDriverBaseNameA(drivers[i], name, MAX_PATH)) {
            continue;
        }
        if (_stricmp(name, target_base_name) == 0) {
            kernel_base = reinterpret_cast<DWORD_PTR>(drivers[i]);
            return true;
        }
    }
    return false;
}

// Loads a private, non-executing copy of a system module purely to read its
// PE headers: DONT_RESOLVE_DLL_REFERENCES skips running the entry point and
// resolving imports, but still maps the image at RVA-correct section
// layout (same layout an ordinary LoadLibrary() would use), which is
// exactly what GetTextSectionRva()/GetProcAddress() below expect -- MSDN
// explicitly documents this flag as intended for reading headers/exports.
HMODULE LoadHeadersOnly(const char* base_file_name) {
    char system_dir[MAX_PATH];
    if (!GetSystemDirectoryA(system_dir, MAX_PATH)) {
        return nullptr;
    }
    char full_path[MAX_PATH];
    std::snprintf(full_path, MAX_PATH, "%s\\%s", system_dir, base_file_name);
    return LoadLibraryExA(full_path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
}

// Submits one kernel module's .text section as an IP filter range, so PT
// tracing/coverage actually reaches the win32k code the harness exercises
// instead of stopping at the thin usermode win32u.dll syscall stubs.
// `filter_index` is one of the 4 hardware IP-filter slots (0-3); index 0
// is already used by SubmitOwnCodeRange() for the harness itself.
void SubmitKernelModuleRange(const char* base_file_name, int filter_index) {
    DWORD_PTR kernel_base = 0;
    if (!FindKernelModuleBase(base_file_name, kernel_base)) {
        HLOG("[-] WARNING: %s not found among loaded kernel modules, "
             "skipping IP range %d\n", base_file_name, filter_index);
        return;
    }

    HMODULE local_copy = LoadHeadersOnly(base_file_name);
    if (!local_copy) {
        HLOG("[-] WARNING: Could not map %s locally to read its headers: %lu\n",
             base_file_name, GetLastError());
        return;
    }

    DWORD_PTR rva = 0, size = 0;
    const bool found_text = GetTextSectionRva(local_copy, rva, size);
    FreeLibrary(local_copy);
    if (!found_text) {
        HLOG("[-] WARNING: %s has no .text section, skipping IP range %d\n",
             base_file_name, filter_index);
        return;
    }

    const DWORD_PTR range_start = kernel_base + rva;
    const DWORD_PTR range_end = range_start + size;

    UINT64 buffer[3] = {0};
    buffer[0] = range_start;
    buffer[1] = range_end;
    buffer[2] = static_cast<UINT64>(filter_index);
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, reinterpret_cast<UINT64>(buffer));

    HLOG("[+] IP filter %d = %s [0x%p - 0x%p]\n", filter_index, base_file_name,
         reinterpret_cast<void*>(range_start), reinterpret_cast<void*>(range_end));
    // Kernel pages can't be VirtualLock'd from usermode; QEMU-Nyx can dump
    // them for the PT decoder on demand regardless (hypercall_api.md).
}

// Uses all 4 hardware IP filter slots on the actual GDI/USER kernel code
// path: our own dispatcher (0), then the real NtGdi implementation, which
// on modern Windows is split across win32kbase.sys/win32kfull.sys, with
// win32k.sys itself reduced to a thin loader/shim (1-3).
//
// Deliberately targeted rather than one giant range spanning all
// addressable memory: Intel PT only has 4 hardware IP-filter slots total
// (a CPU limit, not a kAFL one), so a single catch-all range wouldn't give
// "more" coverage -- it would burn one of only 4 slots on a range that
// also includes every unrelated ntoskrnl subsystem, other kernel drivers,
// the scheduler, interrupts, etc, drowning the coverage bitmap in noise
// that has nothing to do with GDI and slowing down trace decoding/exec
// throughput for no benefit. Precision beats breadth here.
void SubmitKernelCodeRanges() {
    SubmitKernelModuleRange("win32kbase.sys", 1);
    SubmitKernelModuleRange("win32kfull.sys", 2);
    SubmitKernelModuleRange("win32k.sys", 3);
}

// Mirrors driver/target.md's resolve_KeBugCheck(): rewrites the KeBugCheck/
// KeBugCheckEx entry points in the kernel with a PANIC hypercall payload,
// so an actual kernel bugcheck (BSOD) is reported to kAFL as a "Crash"
// finding -- the only kind of finding this harness reports at all, since
// RecoverFromHarnessFault() above deliberately discards usermode harness
// bugs instead of reporting them -- instead of just hanging the guest
// until the fuzzer's timeout detector kills it.
void SubmitKernelPanicHooks() {
    DWORD_PTR kernel_base = 0;
    if (!FindKernelModuleBase("ntoskrnl.exe", kernel_base)) {
        HLOG("[-] WARNING: ntoskrnl.exe not found, kernel BSODs will only "
             "show up as timeouts, not Crash findings\n");
        return;
    }

    HMODULE local_copy = LoadHeadersOnly("ntoskrnl.exe");
    if (!local_copy) {
        HLOG("[-] WARNING: Could not map ntoskrnl.exe locally: %lu\n",
             GetLastError());
        return;
    }

    static const char* const symbols[] = {"KeBugCheck", "KeBugCheckEx"};
    for (const char* symbol : symbols) {
        FARPROC local_proc = GetProcAddress(local_copy, symbol);
        if (!local_proc) {
            HLOG("[-] WARNING: %s not exported by ntoskrnl.exe\n", symbol);
            continue;
        }
        const DWORD_PTR rva = reinterpret_cast<DWORD_PTR>(local_proc) -
                               reinterpret_cast<DWORD_PTR>(local_copy);
        const DWORD_PTR kernel_addr = kernel_base + rva;
        kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC,
                       static_cast<UINT64>(kernel_addr));
        HLOG("[+] SUBMIT_PANIC %s @ 0x%p\n", symbol,
             reinterpret_cast<void*>(kernel_addr));
    }
    FreeLibrary(local_copy);
}

#endif // !KAFL_REPRO_MODE

} // namespace

#ifdef KAFL_REPRO_MODE

// Standalone crash-repro binary: replays a single saved testcase through
// the exact same DispatchGeneratedNtGdi() call the fuzzing binary makes,
// with no kAFL/Nyx hypercalls anywhere in the process. Run this directly
// (e.g. under WinDbg, or with a debugger attached) on a Windows box -- the
// fuzzing VM itself, or any other Windows machine with a matching-enough
// win32k build -- to reproduce and debug a crash found while fuzzing.
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        fprintf(stderr,
                "Replays a single kAFL testcase through the generated NtGdi "
                "dispatcher, without any kAFL/Nyx hypercalls.\n");
        return 2;
    }

    if (!CreateHarnessResources()) {
        DestroyHarnessResources();
        return 1;
    }
    if (!ResolveGeneratedExports()) {
        HLOG("[-] No generated NtGdi exports could be resolved\n");
        DestroyHarnessResources();
        return 1;
    }
    if (!InitializeHandlePools()) {
        HLOG("[-] Handle-pool initialization failed\n");
        DestroyHarnessResources();
        return 1;
    }

    g_vectored_handler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (!g_vectored_handler) {
        HLOG("[-] AddVectoredExceptionHandler failed: %lu\n", GetLastError());
        DestroyHarnessResources();
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "[-] Cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    const long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0) {
        fprintf(stderr, "[-] %s is empty or unreadable\n", argv[1]);
        fclose(f);
        return 1;
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
    const std::size_t bytes_read = fread(buffer.data(), 1, buffer.size(), f);
    fclose(f);
    if (bytes_read != buffer.size()) {
        fprintf(stderr, "[-] Short read on %s (%zu/%zu bytes)\n", argv[1],
                bytes_read, buffer.size());
        return 1;
    }

    fprintf(stderr, "[+] Replaying %s (%zu bytes)\n", argv[1], buffer.size());
    fflush(stderr);

    ResetGeneratedScratch();
    DispatchGeneratedNtGdi(buffer.data(), buffer.size());

    fprintf(stderr, "[+] Dispatch returned without crashing.\n");
    DestroyHarnessResources();
    return 0;
}

#else

int main() {
    HLOG("[+] Initializing generated NtGdi kAFL harness\n");

    if (!CreateHarnessResources()) {
        DestroyHarnessResources();
        return 1;
    }
    if (!ResolveGeneratedExports()) {
        HLOG("[-] No generated NtGdi exports could be resolved\n");
        DestroyHarnessResources();
        return 1;
    }
    if (!InitializeHandlePools()) {
        HLOG("[-] Handle-pool initialization failed\n");
        DestroyHarnessResources();
        return 1;
    }

    g_vectored_handler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (!g_vectored_handler) {
        HLOG("[-] AddVectoredExceptionHandler failed: %lu\n", GetLastError());
        DestroyHarnessResources();
        return 1;
    }

    // Everything above this point becomes part of the pre-snapshot state;
    // everything below runs once per fuzzing session after QEMU restores it.
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    // kAFL/Nyx initialization handshake (nyx_api.h / hypercall_api.md).
    // GET_HOST_CONFIG and SET_AGENT_CONFIG are mandatory: skipping either
    // causes QEMU to abort the guest with
    // "KVM_EXIT_KAFL_GET_HOST_CONFIG/SET_AGENT_CONFIG was not called".
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    host_config_t host_config = {0};
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG,
                   reinterpret_cast<UINT64>(&host_config));
    HLOG("[host_config] bitmap sizes = <0x%x,0x%x>\n",
         host_config.bitmap_size, host_config.ijon_bitmap_size);
    HLOG("[host_config] payload size = %dKB\n",
         host_config.payload_buffer_size / 1024);
    HLOG("[host_config] worker id = %02u\n", host_config.worker_id);

    const SIZE_T payload_buffer_size = host_config.payload_buffer_size;
    HLOG("[+] Allocating kAFL payload buffer\n");
    auto* payload = static_cast<kAFL_payload*>(
        VirtualAlloc(nullptr, payload_buffer_size,
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!payload) {
        HLOG("[-] Payload allocation failed: %lu\n", GetLastError());
        return 1;
    }
    GrowWorkingSetQuota(payload_buffer_size);
    if (!VirtualLock(payload, payload_buffer_size)) {
        HLOG("[-] WARNING: VirtualLock failed to lock payload buffer: %lu\n",
             GetLastError());
    }
    std::memset(payload, 0, payload_buffer_size);

    HLOG("[+] Submitting payload buffer %p\n", payload);
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD,
                   reinterpret_cast<UINT64>(payload));

    // Snapshot mode is enabled (agent_non_reload_mode left unset below), so a
    // single SUBMIT_CR3 before the fuzz loop is sufficient.
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    agent_config_t agent_config = {};
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG,
                   reinterpret_cast<UINT64>(&agent_config));

    SubmitInstrumentationRanges();
    SubmitOwnCodeRange();
    EnableDebugPrivilege();
    SubmitKernelCodeRanges();
    SubmitKernelPanicHooks();

    HLOG("[+] Entering NtGdi fuzz loop\n");
    for (;;) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        std::size_t size = static_cast<std::size_t>(payload->size);
        const std::size_t capacity = payload_buffer_size - offsetof(kAFL_payload, data);
        size = (std::min)(size, capacity);

        // The generated scratch arena is fixed-size and intentionally reused.
        ResetGeneratedScratch();

        // g_handles_* pools only ever grow (RememberHandle() appends every
        // handle a syscall hands back), and PickHandle() selects an entry
        // via `index % pool.size()` -- so the same payload bytes resolve to
        // a different handle depending on how much prior execution grew the
        // pool. QEMU-Nyx's full snapshot restore between iterations resets
        // this incidentally when reload=1, but that makes reproducibility
        // silently depend on the fuzzer's -R setting (and, via --resume, on
        // whatever -R a *previous* invocation of this campaign used).
        // Re-seeding here makes every dispatch self-contained on purpose:
        // cheap (just repopulates the vectors from already-valid handles/
        // stock objects, no GDI resources are recreated), and it trades
        // away discovering bugs that only manifest from state built up
        // across a specific sequence of prior payloads. If that kind of
        // multi-call exploration is wanted later, do it as a deliberate,
        // separate campaign instead of relying on incidental persistence.
        InitializeHandlePools();

        DispatchGeneratedNtGdi(payload->data, size);

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}

#endif // KAFL_REPRO_MODE
