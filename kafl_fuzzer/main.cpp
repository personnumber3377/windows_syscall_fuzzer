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
#include "kafl_user.h"
}

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

[[noreturn]] void KaflPanic(std::uintptr_t code) noexcept {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, static_cast<UINT64>(code));
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
        KaflPanic(static_cast<std::uintptr_t>(code));
    default:
        return EXCEPTION_CONTINUE_SEARCH;
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
        hprintf("[-] GetDC(NULL) failed: %lu\n", GetLastError());
        return false;
    }

    g_resources.memory_dc = CreateCompatibleDC(g_resources.screen_dc);
    if (!g_resources.memory_dc) {
        hprintf("[-] CreateCompatibleDC failed: %lu\n", GetLastError());
        return false;
    }

    g_resources.bitmap =
        CreateCompatibleBitmap(g_resources.screen_dc, 256, 256);
    if (!g_resources.bitmap) {
        hprintf("[-] CreateCompatibleBitmap failed: %lu\n", GetLastError());
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

    hprintf("[+] Resolved %llu/%llu generated exports\n",
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

void SubmitInstrumentationRanges() {
    auto* ranges = static_cast<kAFL_ranges*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!ranges) {
        hprintf("[-] Cannot allocate kAFL range buffer: %lu\n", GetLastError());
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
        return;
    }

    std::memset(ranges, 0xff, 0x1000);
    hprintf("[+] range buffer %p...\n", ranges);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE,
                   reinterpret_cast<UINT64>(ranges));
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
}

} // namespace

int main() {
    hprintf("[+] Initializing generated NtGdi kAFL harness\n");

    if (!CreateHarnessResources()) {
        DestroyHarnessResources();
        return 1;
    }
    if (!ResolveGeneratedExports()) {
        hprintf("[-] No generated NtGdi exports could be resolved\n");
        DestroyHarnessResources();
        return 1;
    }
    if (!InitializeHandlePools()) {
        hprintf("[-] Handle-pool initialization failed\n");
        DestroyHarnessResources();
        return 1;
    }

    g_vectored_handler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (!g_vectored_handler) {
        hprintf("[-] AddVectoredExceptionHandler failed: %lu\n", GetLastError());
        DestroyHarnessResources();
        return 1;
    }

    // Match the initialization order of the working toy harness.
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    hprintf("[+] Allocating kAFL payload buffer\n");
    auto* payload = static_cast<kAFL_payload*>(
        VirtualAlloc(nullptr, PAYLOAD_SIZE,
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!payload) {
        hprintf("[-] Payload allocation failed: %lu\n", GetLastError());
        return 1;
    }
    std::memset(payload, 0, PAYLOAD_SIZE);

    hprintf("[+] Submitting payload buffer %p\n", payload);
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD,
                   reinterpret_cast<UINT64>(payload));
    SubmitInstrumentationRanges();

    hprintf("[+] Entering NtGdi fuzz loop\n");
    for (;;) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

        std::size_t size = static_cast<std::size_t>(payload->size);
        const std::size_t capacity = PAYLOAD_SIZE - offsetof(kAFL_payload, data);
        size = (std::min)(size, capacity);

        // The generated scratch arena is fixed-size and intentionally reused.
        ResetGeneratedScratch();
        DispatchGeneratedNtGdi(payload->data, size);

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}
