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
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

// Keep the generated implementation in this translation unit.
#include "generated_ntgdi_harness.cpp"

// Forward declarations for helpers defined before the stable exported globals.
extern "C" {
extern std::uint8_t g_fuzz_input[];
extern volatile std::size_t g_fuzz_input_length;
extern volatile std::uint64_t g_fuzz_iteration;
}

namespace {

constexpr std::size_t kFuzzBufferCapacity = 10000;
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

struct WarmupConfig {
    std::filesystem::path corpus_directory = L"corpus";
    DWORD startup_delay_ms = 40'000;
    std::size_t mutation_iterations = 20'000;
    std::size_t progress_interval = 250;
};

using Testcase = std::vector<std::uint8_t>;

std::size_t RandomIndex(std::size_t upper_bound) noexcept {
    return upper_bound == 0
        ? 0
        : static_cast<std::size_t>(NextRandom64() % upper_bound);
}

bool ReadTestcaseFile(const std::filesystem::path& path, Testcase& output) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        std::fprintf(stderr, "warning: could not open corpus file: %ls\n",
                     path.c_str());
        return false;
    }

    output.assign(std::istreambuf_iterator<char>(input),
                  std::istreambuf_iterator<char>());

    if (output.size() > kFuzzBufferCapacity) {
        output.resize(kFuzzBufferCapacity);
    }

    return !output.empty();
}

std::vector<Testcase> LoadCorpus(const std::filesystem::path& directory) {
    std::vector<Testcase> corpus;
    std::error_code error;

    if (!std::filesystem::exists(directory, error) ||
        !std::filesystem::is_directory(directory, error)) {
        std::fprintf(stderr,
                     "warning: corpus directory '%ls' does not exist; "
                     "using generated seeds instead.\n",
                     directory.c_str());
        return corpus;
    }

    for (const auto& entry :
         std::filesystem::directory_iterator(directory, error)) {
        if (error) {
            std::fprintf(stderr, "warning: corpus enumeration failed: %s\n",
                         error.message().c_str());
            break;
        }

        if (!entry.is_regular_file(error)) {
            continue;
        }

        Testcase testcase;
        if (ReadTestcaseFile(entry.path(), testcase)) {
            corpus.push_back(std::move(testcase));
        }
    }

    std::printf("Loaded %zu non-empty corpus files from %ls.\n",
                corpus.size(), directory.c_str());
    return corpus;
}

Testcase MakeGeneratedSeed(std::uint16_t syscall_index) {
    Testcase seed(64);
    FillRandomBytes(seed.data(), seed.size());
    seed[0] = static_cast<std::uint8_t>(syscall_index & 0xffu);
    seed[1] = static_cast<std::uint8_t>((syscall_index >> 8) & 0xffu);
    return seed;
}

void EnsureUsableCorpus(std::vector<Testcase>& corpus) {
    if (!corpus.empty()) {
        return;
    }

    // One small generated seed per exported syscall gives the warm-up a chance
    // to touch each top-level dispatch path even when corpus/ is initially empty.
    corpus.reserve(kGeneratedSyscallCount);
    for (std::uint16_t syscall = 0; syscall < kGeneratedSyscallCount; ++syscall) {
        corpus.push_back(MakeGeneratedSeed(syscall));
    }
}

void ClampTestcase(Testcase& testcase) {
    if (testcase.size() > kFuzzBufferCapacity) {
        testcase.resize(kFuzzBufferCapacity);
    }
    if (testcase.size() < 2) {
        testcase.resize(2, 0);
    }
}

Testcase MutateTestcase(const Testcase& seed,
                        const std::vector<Testcase>& corpus) {
    Testcase mutated = seed;
    ClampTestcase(mutated);

    const std::size_t mutation_count = 1 + RandomIndex(8);
    for (std::size_t operation_number = 0;
         operation_number < mutation_count;
         ++operation_number) {
        switch (RandomIndex(7)) {
        case 0: {  // Flip one random bit.
            const std::size_t offset = RandomIndex(mutated.size());
            mutated[offset] ^= static_cast<std::uint8_t>(1u << RandomIndex(8));
            break;
        }
        case 1: {  // Replace one byte.
            const std::size_t offset = RandomIndex(mutated.size());
            mutated[offset] = static_cast<std::uint8_t>(NextRandom64());
            break;
        }
        case 2: {  // Overwrite a short run.
            const std::size_t offset = RandomIndex(mutated.size());
            const std::size_t amount =
                (std::min)(1 + RandomIndex(16), mutated.size() - offset);
            FillRandomBytes(mutated.data() + offset, amount);
            break;
        }
        case 3: {  // Insert random bytes.
            if (mutated.size() < kFuzzBufferCapacity) {
                const std::size_t amount =
                    (std::min)(1 + RandomIndex(16),
                               kFuzzBufferCapacity - mutated.size());
                Testcase inserted(amount);
                FillRandomBytes(inserted.data(), inserted.size());
                const std::size_t offset = RandomIndex(mutated.size() + 1);
                mutated.insert(mutated.begin() + offset,
                               inserted.begin(), inserted.end());
            }
            break;
        }
        case 4: {  // Delete a short run, but retain the syscall selector.
            if (mutated.size() > 2) {
                const std::size_t offset = 2 + RandomIndex(mutated.size() - 2);
                const std::size_t amount =
                    (std::min)(1 + RandomIndex(16), mutated.size() - offset);
                mutated.erase(mutated.begin() + offset,
                              mutated.begin() + offset + amount);
            }
            break;
        }
        case 5: {  // Splice a chunk from another corpus entry.
            if (!corpus.empty()) {
                const Testcase& donor = corpus[RandomIndex(corpus.size())];
                if (!donor.empty()) {
                    const std::size_t donor_offset = RandomIndex(donor.size());
                    const std::size_t amount = (std::min)(
                        1 + RandomIndex(32), donor.size() - donor_offset);
                    const std::size_t output_offset =
                        RandomIndex(mutated.size() + 1);
                    mutated.insert(mutated.begin() + output_offset,
                                   donor.begin() + donor_offset,
                                   donor.begin() + donor_offset + amount);
                    ClampTestcase(mutated);
                }
            }
            break;
        }
        case 6: {  // Occasionally select another valid syscall explicitly.
            const std::uint16_t syscall = static_cast<std::uint16_t>(
                NextRandom64() % kGeneratedSyscallCount);
            mutated[0] = static_cast<std::uint8_t>(syscall & 0xffu);
            mutated[1] = static_cast<std::uint8_t>((syscall >> 8) & 0xffu);
            break;
        }
        }
    }

    ClampTestcase(mutated);
    return mutated;
}

void InstallTestcase(const Testcase& testcase) noexcept {
    // std::memset(g_fuzz_input, 0, sizeof(g_fuzz_input));
    std::memset(g_fuzz_input, 0, 10000);
    const std::size_t length =
        (std::min)(testcase.size(), kFuzzBufferCapacity);
    if (length != 0) {
        std::memcpy(g_fuzz_input, testcase.data(), length);
    }
    g_fuzz_input_length = length;
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
    return DispatchGeneratedNtGdi(
        g_fuzz_input, length);
}

// Keep SEH in a tiny function with no C++ objects that require unwinding.
// This allows the warm-up to continue after ordinary user-mode access
// violations. A genuine kernel bugcheck will still stop the machine, which is
// desirable and cannot safely be swallowed here.
static bool InvokeWarmupIteration() noexcept {
    __try {
        return FuzzOneIteration();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void RunWarmup(const WarmupConfig& config,
                      std::vector<Testcase>& corpus) {
    std::puts("Running every corpus entry once...");

    std::size_t completed = 0;
    std::size_t user_exceptions = 0;

    for (const Testcase& testcase : corpus) {
        InstallTestcase(testcase);
        if (!InvokeWarmupIteration()) {
            ++user_exceptions;
        }
        ++completed;
    }

    std::printf("Base corpus warm-up complete: %zu executions, "
                "%zu user-mode exceptions.\n",
                completed, user_exceptions);

    std::printf("Running %zu lightweight mutation executions...\n",
                config.mutation_iterations);

    for (std::size_t iteration = 0;
         iteration < config.mutation_iterations;
         ++iteration) {
        const Testcase& seed = corpus[RandomIndex(corpus.size())];
        // const Testcase mutated = MutateTestcase(seed, corpus);
        // InstallTestcase(mutated);

        InstallTestcase(seed);

        if (!InvokeWarmupIteration()) {
            ++user_exceptions;
        }

        if (config.progress_interval != 0 &&
            (iteration + 1) % config.progress_interval == 0) {
            std::printf("Warm-up: %zu/%zu mutations, %zu user exceptions.\n",
                        iteration + 1,
                        config.mutation_iterations,
                        user_exceptions);
        }
    }

    ::GdiFlush();
    std::printf("Warm-up finished. Total calls: %zu; user exceptions: %zu.\n",
                completed + config.mutation_iterations,
                user_exceptions);
}


static bool InitializeGeneratedNtGdiExports()
{
    HMODULE win32u = ::GetModuleHandleW(L"win32u.dll");
    HMODULE gdi32 = ::GetModuleHandleW(L"gdi32.dll");

    if (!win32u && !gdi32)
        return false;

    size_t resolved = 0;

    for (size_t i = 0; i < g_generated_ntgdi_export_count; ++i)
    {
        GeneratedNtGdiExport& entry =
            g_generated_ntgdi_exports[i];

        FARPROC address = nullptr;

        if (win32u)
            address = ::GetProcAddress(win32u, entry.name);

        if (!address && gdi32)
            address = ::GetProcAddress(gdi32, entry.name);

        entry.address = address;

        if (address)
            ++resolved;
    }

    return resolved != 0;
}

bool InitializeHandlePools()
{
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

    // Valid user-mode handles.
    if (g_resources.screen_dc)
        g_handles_HDC.push_back(g_resources.screen_dc);

    if (g_resources.memory_dc)
        g_handles_HDC.push_back(g_resources.memory_dc);

    if (g_resources.bitmap)
        g_handles_HBITMAP.push_back(g_resources.bitmap);

    if (g_resources.solid_brush)
        g_handles_HBRUSH.push_back(g_resources.solid_brush);

    if (g_resources.hatch_brush)
        g_handles_HBRUSH.push_back(g_resources.hatch_brush);

    if (g_resources.pen)
        g_handles_HPEN.push_back(g_resources.pen);

    if (g_resources.font)
        g_handles_HFONT.push_back(g_resources.font);

    if (g_resources.region)
        g_handles_HRGN.push_back(g_resources.region);

    if (g_resources.palette)
        g_handles_HPALETTE.push_back(g_resources.palette);

    if (g_resources.desktop_window)
        g_handles_HWND.push_back(g_resources.desktop_window);

    if (g_resources.event_handle)
        g_handles_HANDLE.push_back(g_resources.event_handle);

    // HRESULT isn't really a handle.
    g_handles_HRESULT.push_back(S_OK);
    g_handles_HRESULT.push_back(E_FAIL);
    g_handles_HRESULT.push_back(E_INVALIDARG);

    // Kernel/driver-only handles.
    g_handles_DHPDEV.push_back(nullptr);
    g_handles_DHSURF.push_back(nullptr);
    g_handles_HCOLORSPACE.push_back(nullptr);
    g_handles_HDEV.push_back(nullptr);
    g_handles_HLSURF.push_back(nullptr);
    g_handles_HSURF.push_back(nullptr);
    g_handles_HUMPD.push_back(nullptr);

    // Glyph IDs are integer-like.
    g_handles_HGLYPH.push_back(static_cast<HGLYPH>(0));

    return true;
}

int main() {
    const WarmupConfig config{};

    std::puts("Initializing generated NtGdi snapshot harness...");

    if (!CreateHarnessResources()) {
        DestroyHarnessResources();
        return 1;
    }

    // Resolve all exports and establish stable handle pools before warm-up and
    // before the eventual snapshot.
    if (!InitializeGeneratedNtGdiExports()) {
        std::fputs(
            "warning: one or more generated NtGdi exports were unavailable; "
            "their handlers will be skipped.\n",
            stderr);
    }

    if (!InitializeHandlePools()) {
        std::fputs("InitializeHandlePools failed.\n", stderr);
        DestroyHarnessResources();
        return 1;
    }

    std::printf(
        "Initialization complete. Sleeping for %lu ms. Run lockmem.exe and "
        "perform any debugger setup now.\n",
        static_cast<unsigned long>(config.startup_delay_ms));
    // ::Sleep(config.startup_delay_ms);

    std::vector<Testcase> corpus = LoadCorpus(config.corpus_directory);
    EnsureUsableCorpus(corpus);
    RunWarmup(config, corpus);

    // Prepare a deterministic, completely initialized final input. Set your
    // breakpoint on FuzzOneIteration. The next call is the snapshot call; WTF
    // will later overwrite g_fuzz_input and g_fuzz_input_length after restore.
    std::memset(g_fuzz_input, 0, sizeof(g_fuzz_input));
    g_fuzz_input_length = 2;
    g_fuzz_iteration = 0;

    std::puts("============================================================");
    std::puts("WARM-UP COMPLETE -- SNAPSHOT ON THE NEXT FuzzOneIteration");
    std::puts("Buffer is zeroed; g_fuzz_input_length is 2; syscall index is 0.");
    std::puts("============================================================");
    std::fflush(stdout);
    std::fflush(stderr);

    // Break at the ENTRY of this function and take the snapshot there. Do not
    // move the snapshot point into DispatchGeneratedNtGdi: keeping the stable
    // wrapper entry makes buffer patching and iteration restoration simpler.
    FuzzOneIteration();

    DestroyHarnessResources();
    return 0;
}
