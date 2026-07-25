// main.cpp
//
// Snapshot-oriented driver for generated_ntgdi_harness.cpp.
//
// Build generated_ntgdi_harness.cpp first, place it beside this file, and run
// build.bat from an x64 Visual Studio Developer Command Prompt.
//
// WTF/snapshot integration:
//   * g_fuzz_input and g_fuzz_input_length have C linkage and stable symbols.
//   * Put the snapshot breakpoint at FuzzOneIteration.
//   * Patch g_fuzz_input and g_fuzz_input_length before resuming each iteration.
//   * All DLL export resolution and handle creation happen before the first call
//     to FuzzOneIteration.
//
// The generated implementation is included rather than separately compiled so
// this file can initialize its translation-unit-local static handle pools.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wingdi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// Keep the generated implementation in this translation unit.
#include "generated_ntgdi_harness.cpp"

namespace {

constexpr std::size_t kFuzzBufferCapacity = 1000;
constexpr std::uint16_t kGeneratedSyscallCount = 466;

// Resources owned by the driver. The generated pools merely borrow these
// handles. They remain alive for the lifetime of the process/snapshot.
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

// Small deterministic PRNG. It performs no system calls in the fuzz loop.
std::uint64_t g_prng_state = UINT64_C(0x9e3779b97f4a7c15);

std::uint64_t NextRandom64() noexcept {
    std::uint64_t x = g_prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_prng_state = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

void FillRandomBytes(std::uint8_t* destination, std::size_t size) noexcept {
    std::size_t offset = 0;
    while (offset < size) {
        const std::uint64_t value = NextRandom64();
        const std::size_t amount =
            (std::min)(sizeof(value), size - offset);
        std::memcpy(destination + offset, &value, amount);
        offset += amount;
    }
}

template <typename T>
void AddIfNonNull(std::vector<T>& pool, T value) {
    if (value != nullptr) {
        pool.push_back(value);
    }
}

template <typename T>
void AddNullFallback(std::vector<T>& pool) {
    if (pool.empty()) {
        pool.push_back(static_cast<T>(0));
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
    storage.extra_entries[0]      = {0xff, 0x00, 0x00, 0};
    storage.extra_entries[1]      = {0x00, 0xff, 0x00, 0};
    storage.extra_entries[2]      = {0x00, 0x00, 0xff, 0};

    g_resources.palette =
        ::CreatePalette(reinterpret_cast<const LOGPALETTE*>(&storage));
    return g_resources.palette != nullptr;
}

bool CreateHarnessResources() {
    g_resources.desktop_window = ::GetDesktopWindow();
    g_resources.screen_dc = ::GetDC(nullptr);
    if (!g_resources.screen_dc) {
        std::fprintf(stderr, "GetDC(nullptr) failed: %lu\n",
                     ::GetLastError());
        return false;
    }

    g_resources.memory_dc = ::CreateCompatibleDC(g_resources.screen_dc);
    if (!g_resources.memory_dc) {
        std::fprintf(stderr, "CreateCompatibleDC failed: %lu\n",
                     ::GetLastError());
        return false;
    }

    g_resources.bitmap =
        ::CreateCompatibleBitmap(g_resources.screen_dc, 256, 256);
    if (!g_resources.bitmap) {
        std::fprintf(stderr, "CreateCompatibleBitmap failed: %lu\n",
                     ::GetLastError());
        return false;
    }

    g_resources.old_bitmap =
        ::SelectObject(g_resources.memory_dc, g_resources.bitmap);

    g_resources.solid_brush = ::CreateSolidBrush(RGB(0x40, 0x80, 0xc0));
    g_resources.hatch_brush =
        ::CreateHatchBrush(HS_DIAGCROSS, RGB(0xc0, 0x40, 0x80));
    g_resources.pen =
        ::CreatePen(PS_SOLID, 1, RGB(0x20, 0xe0, 0x70));
    g_resources.font = static_cast<HFONT>(
        ::GetStockObject(DEFAULT_GUI_FONT));
    g_resources.region = ::CreateRectRgn(0, 0, 128, 128);
    g_resources.event_handle =
        ::CreateEventW(nullptr, TRUE, FALSE, nullptr);

    CreatePaletteResource();

    // Exercise enough ordinary GDI setup before the snapshot that lazy user32
    // and gdi32 initialization is less likely to occur in the fuzz iteration.
    ::SelectObject(g_resources.memory_dc, g_resources.solid_brush);
    ::SelectObject(g_resources.memory_dc, g_resources.pen);
    ::SelectObject(g_resources.memory_dc, g_resources.font);
    ::SetBkMode(g_resources.memory_dc, TRANSPARENT);
    ::Rectangle(g_resources.memory_dc, 0, 0, 32, 32);
    ::GdiFlush();

    return true;
}

void DestroyHarnessResources() {
    if (g_resources.memory_dc && g_resources.old_bitmap &&
        g_resources.old_bitmap != HGDI_ERROR) {
        ::SelectObject(g_resources.memory_dc, g_resources.old_bitmap);
    }

    if (g_resources.region) {
        ::DeleteObject(g_resources.region);
    }
    if (g_resources.pen) {
        ::DeleteObject(g_resources.pen);
    }
    if (g_resources.solid_brush) {
        ::DeleteObject(g_resources.solid_brush);
    }
    if (g_resources.hatch_brush) {
        ::DeleteObject(g_resources.hatch_brush);
    }
    if (g_resources.palette) {
        ::DeleteObject(g_resources.palette);
    }
    if (g_resources.bitmap) {
        ::DeleteObject(g_resources.bitmap);
    }
    if (g_resources.memory_dc) {
        ::DeleteDC(g_resources.memory_dc);
    }
    if (g_resources.screen_dc) {
        ::ReleaseDC(nullptr, g_resources.screen_dc);
    }
    if (g_resources.event_handle) {
        ::CloseHandle(g_resources.event_handle);
    }

    g_resources = {};
}

}  // namespace

// Deliberately exported with unmangled C names so WTF can find and patch them.
extern "C" {

__declspec(align(64)) std::uint8_t
    g_fuzz_input[kFuzzBufferCapacity] = {};

volatile std::size_t g_fuzz_input_length = kFuzzBufferCapacity;

volatile std::uint64_t g_fuzz_iteration = 0;

}  // extern "C"

namespace generated_ntgdi {

// This function is defined after including the generated file, so it can access
// its static pools. Reopening the namespace does not change their linkage.
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

    // Common, valid user-mode GDI handles.
    AddIfNonNull(g_handles_HDC, g_resources.screen_dc);
    AddIfNonNull(g_handles_HDC, g_resources.memory_dc);

    AddIfNonNull(g_handles_HBITMAP, g_resources.bitmap);

    AddIfNonNull(g_handles_HBRUSH, g_resources.solid_brush);
    AddIfNonNull(g_handles_HBRUSH, g_resources.hatch_brush);
    AddIfNonNull(
        g_handles_HBRUSH,
        static_cast<HBRUSH>(::GetStockObject(WHITE_BRUSH)));
    AddIfNonNull(
        g_handles_HBRUSH,
        static_cast<HBRUSH>(::GetStockObject(BLACK_BRUSH)));

    AddIfNonNull(g_handles_HPEN, g_resources.pen);
    AddIfNonNull(
        g_handles_HPEN,
        static_cast<HPEN>(::GetStockObject(BLACK_PEN)));

    AddIfNonNull(g_handles_HFONT, g_resources.font);
    AddIfNonNull(
        g_handles_HFONT,
        static_cast<HFONT>(::GetStockObject(SYSTEM_FONT)));

    AddIfNonNull(g_handles_HRGN, g_resources.region);
    AddIfNonNull(g_handles_HPALETTE, g_resources.palette);
    AddIfNonNull(g_handles_HWND, g_resources.desktop_window);
    AddIfNonNull(g_handles_HANDLE, g_resources.event_handle);

    // HRESULT is a scalar status code, not a kernel/GDI handle. The generated
    // graph classified it as a handle because its name begins with H. Keep a
    // small value pool until the generator is corrected to classify HRESULT as
    // a signed 32-bit integer.
    g_handles_HRESULT.push_back(S_OK);
    g_handles_HRESULT.push_back(E_FAIL);
    g_handles_HRESULT.push_back(E_INVALIDARG);

    // Driver/engine-specific handles cannot be created safely using ordinary
    // documented GDI setup. A null entry keeps 16-bit pool selection bounded
    // and lets individual syscalls reject unsupported objects naturally.
    AddNullFallback(g_handles_DHPDEV);
    AddNullFallback(g_handles_DHSURF);
    AddNullFallback(g_handles_HCOLORSPACE);
    AddNullFallback(g_handles_HDEV);
    AddNullFallback(g_handles_HLSURF);
    AddNullFallback(g_handles_HSURF);
    AddNullFallback(g_handles_HUMPD);

    // HGLYPH is commonly an integer-like glyph identifier rather than a real
    // HANDLE. Zero is a safe initial corpus value.
    if (g_handles_HGLYPH.empty()) {
        g_handles_HGLYPH.push_back(static_cast<HGLYPH>(0));
    }

    // Every pool must contain at least one element because generated decoders
    // select entries using a serialized uint16_t index.
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

}  // namespace generated_ntgdi

// Keep this function uninlined and externally visible: it is a convenient,
// stable snapshot target. Do not add exception/SEH handling around Dispatch;
// genuine faults must remain visible to the fuzzer.
extern "C" __declspec(noinline) bool FuzzOneIteration() {
    std::size_t length = g_fuzz_input_length;
    if (length > kFuzzBufferCapacity) {
        length = kFuzzBufferCapacity;
    }

    ++g_fuzz_iteration;
    return generated_ntgdi::DispatchGeneratedNtGdi(
        g_fuzz_input, length);
}

int main() {
    std::puts("Initializing generated NtGdi snapshot harness...");

    if (!CreateHarnessResources()) {
        DestroyHarnessResources();
        return 1;
    }

    // Resolve every exported function before the snapshot. No loader lookup
    // should occur in DispatchGeneratedNtGdi afterward.
    const bool all_exports_resolved =
        generated_ntgdi::InitializeGeneratedNtGdiExports();
    if (!all_exports_resolved) {
        std::fputs(
            "warning: one or more generated NtGdi exports were unavailable; "
            "their handlers will be skipped.\n",
            stderr);
    }

    if (!generated_ntgdi::InitializeHandlePools()) {
        std::fputs("InitializeHandlePools failed.\n", stderr);
        DestroyHarnessResources();
        return 1;
    }

    // Generate a usable standalone smoke-test input. WTF will overwrite these
    // globals after restoring the snapshot.
    FillRandomBytes(g_fuzz_input, kFuzzBufferCapacity);
    g_fuzz_input_length = kFuzzBufferCapacity;

    // Purely random first words are usually outside [0, 465]. Choose a valid
    // syscall for standalone execution while leaving the remaining bytes random.
    const std::uint16_t initial_syscall =
        static_cast<std::uint16_t>(NextRandom64() %
                                   kGeneratedSyscallCount);
    g_fuzz_input[0] =
        static_cast<std::uint8_t>(initial_syscall & 0xffu);
    g_fuzz_input[1] =
        static_cast<std::uint8_t>((initial_syscall >> 8) & 0xffu);

    std::puts(
        "Initialization complete. Snapshot at FuzzOneIteration and patch "
        "g_fuzz_input plus g_fuzz_input_length.");

    // Standalone random smoke loop. Under WTF, take the snapshot at the entry
    // of FuzzOneIteration and restore it for each testcase.
    for (;;) {
        FillRandomBytes(g_fuzz_input, kFuzzBufferCapacity);

        const std::uint16_t syscall_index =
            static_cast<std::uint16_t>(
                NextRandom64() % kGeneratedSyscallCount);
        g_fuzz_input[0] =
            static_cast<std::uint8_t>(syscall_index & 0xffu);
        g_fuzz_input[1] =
            static_cast<std::uint8_t>((syscall_index >> 8) & 0xffu);
        g_fuzz_input_length = kFuzzBufferCapacity;

        FuzzOneIteration();
    }
}
