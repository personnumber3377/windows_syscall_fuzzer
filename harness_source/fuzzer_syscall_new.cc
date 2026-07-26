#include "backend.h"
#include "targets.h"
#include "crash_detection_umode.h"
#include "debugger.h"
#include "globals.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fmt/format.h>
#include <string>

namespace NTGDIFUZZER {

constexpr bool Log = true;

template <typename... Args>
void MLog(const char *Fmt, const Args &...ArgsList) {
  if constexpr (Log) {
    fmt::print("NTGDIFUZZER: ");
    fmt::print(fmt::runtime(Fmt), ArgsList...);
  }
}

static std::string Hex(uint64_t Value) {
  return fmt::format("{:#x}", Value);
}

/*
 * ntgdi_fuzzer.exe layout from the supplied Ghidra listing.
 *
 * Preferred image base: 0x140000000
 *
 *   0x140028f39  top of original fuzzing loop
 *   0x140028f45  patched CALL FillRandomBytes (currently EB FE 90 90 90)
 *   0x140028f4a  random syscall-selection block begins
 *   0x140028fce  CALL FuzzOneIteration
 *   0x140028fd4  JMP back to 0x140028f39
 *
 *   0x14010c000  g_fuzz_input_length (uint64_t)
 *   0x14010eb00  g_fuzz_input        (10,000-byte static buffer)
 *
 * InsertTestcase resumes at RVA_FuzzOneIterationCall. This skips:
 *   - FillRandomBytes
 *   - NextRandom64
 *   - random syscall-index generation
 *   - writes to g_fuzz_input[0] and g_fuzz_input[1]
 *   - the hard-coded g_fuzz_input_length = 0x2710 assignment
 *
 * Therefore testcase bytes 0 and 1 remain under fuzzer control and are read
 * by DispatchGeneratedNtGdi as its little-endian uint16_t syscall index.
 */


/*
constexpr uint64_t RVA_LoopStart             = 0x28f39;
constexpr uint64_t RVA_PatchedFillRandomCall = 0x28f45;
constexpr uint64_t RVA_FuzzOneIterationCall  = 0x28fce;
constexpr uint64_t RVA_g_fuzz_input_length   = 0x10c000;
constexpr uint64_t RVA_g_fuzz_input          = 0x10eb00;
*/

constexpr uint64_t RVA_Main                  = 0x28ef0;

constexpr uint64_t RVA_FillRandomBytes       = 0x280d0;
constexpr uint64_t RVA_FillRandomBytesCall   = 0x28f8e;

constexpr uint64_t RVA_FuzzOneIteration      = 0x28a00;
constexpr uint64_t RVA_FuzzOneIterationCall  = 0x291f0;
constexpr uint64_t RVA_AfterFuzzOneIteration = 0x291f5;

constexpr uint64_t RVA_g_fuzz_input_length   = 0x178000;
constexpr uint64_t RVA_g_fuzz_input          = 0x17bd80;

constexpr size_t MAX_TESTCASE_SIZE = 0x2710;
constexpr size_t SYSCALL_INDEX_SIZE = sizeof(uint16_t);

static uint64_t ModuleBase = 0;
static Gva_t LoopStart;
static Gva_t PatchedFillRandomCall;
static Gva_t FuzzOneIterationCall;
static Gva_t GFuzzInputLength;
static Gva_t GFuzzInput;

static bool WriteBytes(Backend_t *Backend,
                       Gva_t Address,
                       const void *Data,
                       size_t Size) {
  if (Size == 0) {
    return true;
  }

  return Backend->VirtWriteDirty(
      Address,
      reinterpret_cast<const uint8_t *>(Data),
      Size);
}

static bool WriteU64(Backend_t *Backend, Gva_t Address, uint64_t Value) {
  return WriteBytes(Backend, Address, &Value, sizeof(Value));
}

static std::string CrashSig(Backend_t *Backend, const char *Tag) {
  return fmt::format(
      "{}-rip-{}-rax-{}-rcx-{}-rdx-{}-r8-{}-r9-{}",
      Tag,
      Hex(Backend->GetReg(Registers_t::Rip)),
      Hex(Backend->GetReg(Registers_t::Rax)),
      Hex(Backend->GetReg(Registers_t::Rcx)),
      Hex(Backend->GetReg(Registers_t::Rdx)),
      Hex(Backend->GetReg(Registers_t::R8)),
      Hex(Backend->GetReg(Registers_t::R9)));
}

bool Restore() {
  return true;
}

/*
bool InsertTestcase(const uint8_t *Data, const size_t Size) {
  if (Data == nullptr && Size != 0) {
    fmt::print("NTGDIFUZZER: non-zero testcase size with null data\n");
    return false;
  }

  const size_t CopySize = std::min(Size, MAX_TESTCASE_SIZE);

  // Preserve bytes 0-1: DispatchGeneratedNtGdi consumes them as the index.
  if (CopySize != 0 &&
      !WriteBytes(g_Backend, GFuzzInput, Data, CopySize)) {
    fmt::print("NTGDIFUZZER: failed to write testcase\n");
    return false;
  }

  // Deterministic short-input padding without crossing the static buffer.
  if (CopySize < MAX_TESTCASE_SIZE) {
    constexpr std::array<uint8_t, 32> ZeroTail{};
    const size_t Remaining = MAX_TESTCASE_SIZE - CopySize;
    const size_t TailSize = std::min(Remaining, ZeroTail.size());

    if (!WriteBytes(g_Backend,
                    Gva_t(GFuzzInput.U64() + CopySize),
                    ZeroTail.data(),
                    TailSize)) {
      fmt::print("NTGDIFUZZER: failed to clear testcase tail\n");
      return false;
    }
  }

  // Skip the target's later hard-coded length assignment and set the true size.
  if (!WriteU64(g_Backend,
                GFuzzInputLength,
                static_cast<uint64_t>(CopySize))) {
    fmt::print("NTGDIFUZZER: failed to update g_fuzz_input_length\n");
    return false;
  }

  if constexpr (Log) {
    uint16_t SyscallIndex = 0xffff;

    if (CopySize >= SYSCALL_INDEX_SIZE) {
      std::memcpy(&SyscallIndex, Data, sizeof(SyscallIndex));
      MLog("size={} syscall_index={}\n", CopySize, SyscallIndex);
    } else {
      MLog("size={} (too short for syscall index)\n", CopySize);
    }
  }

  // Jump directly to CALL FuzzOneIteration.
  g_Backend->SetReg(Registers_t::Rip, FuzzOneIterationCall.U64());
  return true;
}
*/

bool InsertTestcase(const uint8_t *Data, const size_t Size) {
    if (Data == nullptr && Size != 0) {
        return false;
    }

    const size_t CopySize = std::min(Size, MAX_TESTCASE_SIZE);

    if (CopySize != 0 &&
        !WriteBytes(g_Backend, GFuzzInput, Data, CopySize)) {
        return false;
    }

    if (CopySize < MAX_TESTCASE_SIZE) {
        constexpr std::array<uint8_t, 32> ZeroTail{};
        const size_t TailSize =
            std::min(MAX_TESTCASE_SIZE - CopySize, ZeroTail.size());

        if (!WriteBytes(
                g_Backend,
                Gva_t(GFuzzInput.U64() + CopySize),
                ZeroTail.data(),
                TailSize)) {
            return false;
        }
    }

    if (!WriteU64(
            g_Backend,
            GFuzzInputLength,
            static_cast<uint64_t>(CopySize))) {
        return false;
    }

    /*
     * Redirect lifecycle-only syscall 0.
     *
     * Prefer changing the generated dispatcher permanently. This target-side
     * guard also protects old corpus entries while testing.
     */
    if (CopySize >= 2) {
        uint16_t Index = 0;
        std::memcpy(&Index, Data, sizeof(Index));

        if (Index == 0) {
            constexpr uint16_t SafeIndex = 1;

            if (!WriteBytes(
                    g_Backend,
                    GFuzzInput,
                    &SafeIndex,
                    sizeof(SafeIndex))) {
                return false;
            }
        }
    }

    g_Backend->SetReg(
        Registers_t::Rip,
        FuzzOneIterationCall.U64());

    return true;
}

bool Init(const Options_t &, const CpuState_t &) {
  if (!SetupUsermodeCrashDetectionHooks()) {
    fmt::print("NTGDIFUZZER: failed to set up user-mode crash hooks\n");
    return false;
  }

  ModuleBase = g_Dbg->GetModuleBase("ntgdi_fuzzer");
  if (ModuleBase == 0) {
    ModuleBase = g_Dbg->GetModuleBase("ntgdi_fuzzer.exe");
  }
  if (ModuleBase == 0) {
    fmt::print("NTGDIFUZZER: could not find ntgdi_fuzzer module base\n");
    return false;
  }

  LoopStart             = Gva_t(ModuleBase + RVA_LoopStart);
  PatchedFillRandomCall = Gva_t(ModuleBase + RVA_PatchedFillRandomCall);
  FuzzOneIterationCall  = Gva_t(ModuleBase + RVA_FuzzOneIterationCall);
  GFuzzInputLength      = Gva_t(ModuleBase + RVA_g_fuzz_input_length);
  GFuzzInput            = Gva_t(ModuleBase + RVA_g_fuzz_input);

  MLog("ModuleBase={}\n", Hex(ModuleBase));
  MLog("LoopStart={}\n", Hex(LoopStart.U64()));
  MLog("PatchedFillRandomCall={}\n", Hex(PatchedFillRandomCall.U64()));
  MLog("FuzzOneIterationCall={}\n", Hex(FuzzOneIterationCall.U64()));
  MLog("g_fuzz_input_length={}\n", Hex(GFuzzInputLength.U64()));
  MLog("g_fuzz_input={}\n", Hex(GFuzzInput.U64()));

  // One testcase completed when main returns to the original loop head.
  g_Backend->SetBreakpoint(LoopStart, [](Backend_t *Backend) {
    Backend->Stop(Ok_t());
  });

  g_Backend->SetBreakpoint("ntdll!RtlFailFast2", [](Backend_t *Backend) {
    Backend->Stop(Crash_t(CrashSig(Backend, "FAILFAST")));
  });

  g_Backend->SetBreakpoint(
      "ntdll!RtlReportCriticalFailure",
      [](Backend_t *Backend) {
        Backend->Stop(Crash_t(CrashSig(Backend, "CRITICAL")));
      });

  g_Backend->SetBreakpoint("ucrtbase!abort", [](Backend_t *Backend) {
    Backend->Stop(Crash_t(CrashSig(Backend, "ABORT")));
  });

  g_Backend->SetBreakpoint("ucrtbased!abort", [](Backend_t *Backend) {
    Backend->Stop(Crash_t(CrashSig(Backend, "ABORTD")));
  });

  g_Backend->SetBreakpoint(
      "KERNELBASE!RaiseException",
      [](Backend_t *Backend) {
        const uint32_t Code = static_cast<uint32_t>(Backend->GetArg(0));

        if (Code == 0xE06D7363) {
          Backend->Stop(Ok_t());
          return;
        }

        Backend->Stop(Crash_t(fmt::format(
            "{}-code-{}",
            CrashSig(Backend, "RAISEEXCEPTION"),
            Hex(Code))));
      });

  g_Backend->SetBreakpoint("nt!KeBugCheckEx", [](Backend_t *Backend) {
    Backend->Stop(Crash_t(fmt::format(
        "bugcheck-code-{}-p1-{}-p2-{}-p3-{}-rip-{}",
        Hex(Backend->GetReg(Registers_t::Rcx)),
        Hex(Backend->GetReg(Registers_t::Rdx)),
        Hex(Backend->GetReg(Registers_t::R8)),
        Hex(Backend->GetReg(Registers_t::R9)),
        Hex(Backend->GetReg(Registers_t::Rip)))));
  });

  return true;
}

Target_t NtGdiFuzzerTarget(
    "ntgdi_fuzzer",
    Init,
    InsertTestcase,
    Restore);

} // namespace NTGDIFUZZER