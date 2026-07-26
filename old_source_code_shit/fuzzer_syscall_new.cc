#include "backend.h"
#include "targets.h"
#include "crash_detection_umode.h"
#include "debugger.h"
#include "globals.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fmt/format.h>
#include <string>

#include <fstream>

namespace NTGDIFUZZER {

constexpr bool Log = true;

template <typename... Args>
void MLog(const char *Fmt, const Args &...ArgsList) {
  if constexpr (Log) {
    fmt::print("NTGDIFUZZER: ");
    fmt::print(fmt::runtime(Fmt), ArgsList...);
  }
}

static std::string Hex(const uint64_t Value) {
  return fmt::format("{:#x}", Value);
}

/*
 * ntgdi_fuzzer.exe layout for this exact binary.
 *
 * Preferred image base:
 *
 *     0x140000000
 *
 * Runtime layout around the snapshot:
 *
 *     RVA 0x291eb:
 *
 *         EB FE               jmp $
 *         90                  nop
 *         90                  nop
 *         90                  nop
 *
 *     RVA 0x291f0:
 *
 *         E8 xx xx xx xx      call FuzzOneIteration
 *
 *     RVA 0x291f5:
 *
 *         E8 xx xx xx xx      call DestroyHarnessResources
 *
 * The snapshot was captured while RIP pointed at RVA 0x291eb.
 *
 * Therefore:
 *
 *     snapshot RIP + 5 == RVA 0x291f0
 *
 * InsertTestcase redirects RIP to the real CALL instruction. Executing the
 * CALL normally pushes RVA 0x291f5 as the return address. The breakpoint at
 * RVA 0x291f5 then marks successful completion of one fuzz iteration.
 *
 * Globals:
 *
 *     RVA 0x178000  uint64_t g_fuzz_input_length
 *     RVA 0x17bd80  uint8_t  g_fuzz_input[10000]
 *
 * The first two testcase bytes are consumed as the little-endian generated
 * NtGdi syscall index.
 */

constexpr uint64_t RVA_Main = 0x28ef0;

constexpr uint64_t RVA_FuzzOneIteration = 0x28a00;

/*
 * Snapshot and execution-control locations.
 */
constexpr uint64_t RVA_SnapshotLoop = 0x291eb;
constexpr uint64_t RVA_FuzzOneIterationCall = 0x291f0;
constexpr uint64_t RVA_AfterFuzzOneIteration = 0x291f5;

/*
 * Distance from the snapshot's EB FE instruction to the real CALL.
 */
constexpr uint64_t SNAPSHOT_TO_CALL_DELTA =
    RVA_FuzzOneIterationCall - RVA_SnapshotLoop;

static_assert(SNAPSHOT_TO_CALL_DELTA == 5);

/*
 * Testcase globals.
 */
constexpr uint64_t RVA_g_fuzz_input_length = 0x178000;
constexpr uint64_t RVA_g_fuzz_input = 0x17bd80;

constexpr size_t MAX_TESTCASE_SIZE = 0x2710;  // 10,000 bytes
constexpr size_t SYSCALL_INDEX_SIZE = sizeof(uint16_t);

/*
 * Clearing only a tiny suffix can leave bytes from the seed testcase visible
 * beyond the logical testcase length. Clear the complete unused suffix in
 * manageable chunks instead.
 */
constexpr size_t ZERO_CHUNK_SIZE = 0x400;

static uint64_t ModuleBase = 0;

static Gva_t SnapshotLoop;
static Gva_t FuzzOneIterationCall;
static Gva_t AfterFuzzOneIteration;
static Gva_t GFuzzInputLength;
static Gva_t GFuzzInput;

static bool WriteBytes(Backend_t *Backend,
                       const Gva_t Address,
                       const void *Data,
                       const size_t Size) {
  if (Size == 0) {
    return true;
  }

  if (Backend == nullptr || Data == nullptr) {
    return false;
  }

  return Backend->VirtWriteDirty(
      Address,
      reinterpret_cast<const uint8_t *>(Data),
      Size);
}

static bool WriteU64(Backend_t *Backend,
                     const Gva_t Address,
                     const uint64_t Value) {
  return WriteBytes(Backend, Address, &Value, sizeof(Value));
}

static bool ClearRange(Backend_t *Backend,
                       const Gva_t Start,
                       size_t Size) {
  constexpr std::array<uint8_t, ZERO_CHUNK_SIZE> Zeros{};

  uint64_t Address = Start.U64();

  while (Size != 0) {
    const size_t ChunkSize = std::min(Size, Zeros.size());

    if (!WriteBytes(
            Backend,
            Gva_t(Address),
            Zeros.data(),
            ChunkSize)) {
      return false;
    }

    Address += ChunkSize;
    Size -= ChunkSize;
  }

  return true;
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

/*
 * WTF restores the original snapshot independently. There is no additional
 * target-specific state to rebuild here.
 */
bool Restore() {
  return true;
}

bool InsertTestcase(const uint8_t *Data, const size_t Size) {
  if (Data == nullptr && Size != 0) {
    fmt::print(
        "NTGDIFUZZER: non-zero testcase size with null data\n");
    return false;
  }

  const size_t CopySize = std::min(Size, MAX_TESTCASE_SIZE);

  /*
   * Write the testcase exactly as generated.
   *
   * In particular, bytes 0 and 1 remain controlled by the fuzzer because
   * FuzzOneIteration/DispatchGeneratedNtGdi uses them as the syscall index.
   */
  if (CopySize != 0 &&
      !WriteBytes(
          g_Backend,
          GFuzzInput,
          Data,
          CopySize)) {
    fmt::print(
        "NTGDIFUZZER: failed to write {} testcase bytes at {}\n",
        CopySize,
        Hex(GFuzzInput.U64()));
    return false;
  }

  /*
   * Deterministically clear every byte after the logical testcase.
   *
   * This prevents a short testcase from inheriting suffix bytes from the
   * original fileinput.bin contents stored in the snapshot.
   */
  if (CopySize < MAX_TESTCASE_SIZE) {
    const Gva_t TailAddress(
        GFuzzInput.U64() + static_cast<uint64_t>(CopySize));

    const size_t TailSize = MAX_TESTCASE_SIZE - CopySize;

    if (!ClearRange(g_Backend, TailAddress, TailSize)) {
      fmt::print(
          "NTGDIFUZZER: failed to clear {} bytes at testcase tail {}\n",
          TailSize,
          Hex(TailAddress.U64()));
      return false;
    }
  }

  /*
   * g_fuzz_input_length is a uint64_t.
   */
  if (!WriteU64(
          g_Backend,
          GFuzzInputLength,
          static_cast<uint64_t>(CopySize))) {
    fmt::print(
        "NTGDIFUZZER: failed to write g_fuzz_input_length at {}\n",
        Hex(GFuzzInputLength.U64()));
    return false;
  }

  if constexpr (Log) {
    if (CopySize >= SYSCALL_INDEX_SIZE) {
      uint16_t SyscallIndex = 0;
      std::memcpy(
          &SyscallIndex,
          Data,
          sizeof(SyscallIndex));

      MLog(
          "size={} syscall_index={} snapshot_rip={} execution_rip={}\n",
          CopySize,
          SyscallIndex,
          Hex(SnapshotLoop.U64()),
          Hex(FuzzOneIterationCall.U64()));
    } else {
      MLog(
          "size={} too-short-for-syscall-index "
          "snapshot_rip={} execution_rip={}\n",
          CopySize,
          Hex(SnapshotLoop.U64()),
          Hex(FuzzOneIterationCall.U64()));
    }
  }

  /*
   * The snapshot RIP points at:
   *
   *     EB FE 90 90 90
   *
   * The CALL starts five bytes later.
   *
   * Setting RIP to the CALL rather than directly to FuzzOneIteration ensures
   * the CPU executes a real CALL and naturally pushes the correct return
   * address, RVA 0x291f5, onto the user-mode stack.
   */
  const uint64_t CurrentRip =
      g_Backend->GetReg(Registers_t::Rip);

  const uint64_t ExpectedSnapshotRip =
      SnapshotLoop.U64();

  if (CurrentRip != ExpectedSnapshotRip) {
    fmt::print(
        "NTGDIFUZZER: unexpected restored RIP {}; expected {}\n",
        Hex(CurrentRip),
        Hex(ExpectedSnapshotRip));
    return false;
  }

  /*
   * This is deliberately expressed as RIP + 5, matching the snapshot layout.
   */
  g_Backend->SetReg(
      Registers_t::Rip,
      CurrentRip + SNAPSHOT_TO_CALL_DELTA);

  {
      std::ofstream out("wtf_buffer.bin", std::ios::binary);

      if (out) {
          // Entire 10000-byte buffer.

          out.write(reinterpret_cast<const char *>(Data), CopySize);

          std::array<char, MAX_TESTCASE_SIZE> zeros{};

          if (CopySize < MAX_TESTCASE_SIZE) {
              out.write(
                  zeros.data(),
                  MAX_TESTCASE_SIZE - CopySize);
          }

          out.close();
      }

      std::ofstream meta("wtf_length.txt");

      if (meta) {
          meta << CopySize << "\n";
      }
  }

  return true;
}

bool Init(const Options_t &, const CpuState_t &) {
  if (!SetupUsermodeCrashDetectionHooks()) {
    fmt::print(
        "NTGDIFUZZER: failed to set up user-mode crash hooks\n");
    return false;
  }

  ModuleBase = g_Dbg->GetModuleBase("ntgdi_fuzzer");

  if (ModuleBase == 0) {
    ModuleBase =
        g_Dbg->GetModuleBase("ntgdi_fuzzer.exe");
  }

  if (ModuleBase == 0) {
    fmt::print(
        "NTGDIFUZZER: could not find ntgdi_fuzzer module base\n");
    return false;
  }

  SnapshotLoop =
      Gva_t(ModuleBase + RVA_SnapshotLoop);

  FuzzOneIterationCall =
      Gva_t(ModuleBase + RVA_FuzzOneIterationCall);

  AfterFuzzOneIteration =
      Gva_t(ModuleBase + RVA_AfterFuzzOneIteration);

  GFuzzInputLength =
      Gva_t(ModuleBase + RVA_g_fuzz_input_length);

  GFuzzInput =
      Gva_t(ModuleBase + RVA_g_fuzz_input);

  MLog("ModuleBase={}\n", Hex(ModuleBase));
  MLog("SnapshotLoop={}\n", Hex(SnapshotLoop.U64()));
  MLog(
      "FuzzOneIterationCall={}\n",
      Hex(FuzzOneIterationCall.U64()));
  MLog(
      "AfterFuzzOneIteration={}\n",
      Hex(AfterFuzzOneIteration.U64()));
  MLog(
      "g_fuzz_input_length={}\n",
      Hex(GFuzzInputLength.U64()));
  MLog(
      "g_fuzz_input={}\n",
      Hex(GFuzzInput.U64()));
  MLog(
      "MAX_TESTCASE_SIZE={:#x} ({})\n",
      MAX_TESTCASE_SIZE,
      MAX_TESTCASE_SIZE);

  const uint64_t InitialRip =
      g_Backend->GetReg(Registers_t::Rip);

  if (InitialRip != SnapshotLoop.U64()) {
    fmt::print(
        "NTGDIFUZZER: snapshot RIP mismatch\n"
        "  restored RIP: {}\n"
        "  expected RIP: {}\n"
        "The snapshot must be taken at ntgdi_fuzzer+{:#x}.\n",
        Hex(InitialRip),
        Hex(SnapshotLoop.U64()),
        RVA_SnapshotLoop);
    return false;
  }

  /*
   * Normal testcase completion.
   *
   * The CALL at RVA 0x291f0 pushes RVA 0x291f5. Once
   * FuzzOneIteration returns, this breakpoint is reached before
   * DestroyHarnessResources executes.
   */
  g_Backend->SetBreakpoint(
      AfterFuzzOneIteration,
      [](Backend_t *Backend) {
        Backend->Stop(Ok_t());
      });

  /*
   * Additional user-mode crash conditions.
   */
  g_Backend->SetBreakpoint(
      "ntdll!RtlFailFast2",
      [](Backend_t *Backend) {
        Backend->Stop(
            Crash_t(CrashSig(Backend, "FAILFAST")));
      });

  g_Backend->SetBreakpoint(
      "ntdll!RtlReportCriticalFailure",
      [](Backend_t *Backend) {
        Backend->Stop(
            Crash_t(CrashSig(Backend, "CRITICAL")));
      });

  g_Backend->SetBreakpoint(
      "ucrtbase!abort",
      [](Backend_t *Backend) {
        Backend->Stop(
            Crash_t(CrashSig(Backend, "ABORT")));
      });

  g_Backend->SetBreakpoint(
      "ucrtbased!abort",
      [](Backend_t *Backend) {
        Backend->Stop(
            Crash_t(CrashSig(Backend, "ABORTD")));
      });

  g_Backend->SetBreakpoint(
    Gva_t(0xfffff802f385df41ULL), // "win32kfull!PFEOBJ::bFilteredOut+0x31",
    [](Backend_t *Backend) {

        fmt::print(
            "\n==================== PFEOBJ::bFilteredOut ====================\n");

        fmt::print("RIP = {}\n",
            Hex(Backend->GetReg(Registers_t::Rip)));

        fmt::print("RAX = {}\n",
            Hex(Backend->GetReg(Registers_t::Rax)));

        fmt::print("RBX = {}\n",
            Hex(Backend->GetReg(Registers_t::Rbx)));

        fmt::print("RCX = {}\n",
            Hex(Backend->GetReg(Registers_t::Rcx)));

        fmt::print("RDX = {}\n",
            Hex(Backend->GetReg(Registers_t::Rdx)));

        fmt::print("R8  = {}\n",
            Hex(Backend->GetReg(Registers_t::R8)));

        fmt::print("R9  = {}\n",
            Hex(Backend->GetReg(Registers_t::R9)));

        fmt::print("RSP = {}\n",
            Hex(Backend->GetReg(Registers_t::Rsp)));

        fmt::print("RBP = {}\n",
            Hex(Backend->GetReg(Registers_t::Rbp)));

        Backend->Stop(Ok_t());
    });

  /*
   * Ignore ordinary MSVC C++ exceptions because generated syscall handlers
   * may deliberately catch or reject malformed arguments through exceptions.
   *
   * All other RaiseException calls are classified as crashes.
   */
  g_Backend->SetBreakpoint(
      "KERNELBASE!RaiseException",
      [](Backend_t *Backend) {
        const uint32_t Code =
            static_cast<uint32_t>(Backend->GetArg(0));

        if (Code == 0xE06D7363) {
          Backend->Stop(Ok_t());
          return;
        }

        Backend->Stop(Crash_t(fmt::format(
            "{}-code-{}",
            CrashSig(Backend, "RAISEEXCEPTION"),
            Hex(Code))));
      });

  /*
   * Kernel bugcheck.
   *
   * KeBugCheckEx arguments on Windows x64:
   *
   *     RCX = bugcheck code
   *     RDX = parameter 1
   *     R8  = parameter 2
   *     R9  = parameter 3
   *
   * The RIP here is KeBugCheckEx itself, so the parameters are more useful
   * than treating RIP as the original fault location.
   */
  g_Backend->SetBreakpoint(
      "nt!KeBugCheckEx",
      [](Backend_t *Backend) {
        const uint64_t BugcheckCode =
            Backend->GetReg(Registers_t::Rcx);

        const uint64_t Parameter1 =
            Backend->GetReg(Registers_t::Rdx);

        const uint64_t Parameter2 =
            Backend->GetReg(Registers_t::R8);

        const uint64_t Parameter3 =
            Backend->GetReg(Registers_t::R9);

        Backend->Stop(Crash_t(fmt::format(
            "bugcheck-code-{}-p1-{}-p2-{}-p3-{}",
            Hex(BugcheckCode),
            Hex(Parameter1),
            Hex(Parameter2),
            Hex(Parameter3))));
      });

  return true;
}

Target_t NtGdiFuzzerTarget(
    "ntgdi_fuzzer",
    Init,
    InsertTestcase,
    Restore);

}  // namespace NTGDIFUZZER
