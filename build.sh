#!/usr/bin/env bash
set -euo pipefail

CXX="${CXX:-x86_64-w64-mingw32-g++}"
KAFL_INCLUDE="${KAFL_INCLUDE:-../}"
OUT_DIR="${OUT_DIR:-build}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$OUT_DIR"

# ddk_headers/ vendors the ReactOS-derived winddi.h/d3dnthal.h/ntgdi.h/etc.
# that generated_ntgdi_harness.cpp was generated against. MinGW's own
# winddi.h references a d3dnthal.h it doesn't ship, and its own
# d3dtypes.h/d3dcaps.h are the modern DirectX SDK versions, incompatible
# with the old D3D NT HAL structures the generated file decodes. This
# path must come before system include dirs so it consistently wins.
"$CXX" \
  -std=gnu++17 \
  -O0 -g3 \
  -Wall -Wextra -Wpedantic \
  -Wno-cast-function-type \
  -Wno-unused-function \
  -Wno-unused-variable \
  -fno-omit-frame-pointer \
  -fno-exceptions \
  -fno-rtti \
  -DWIN32_LEAN_AND_MEAN \
  -DNOMINMAX \
  -D_CRT_SECURE_NO_WARNINGS \
  -I"$SCRIPT_DIR/ddk_headers" \
  -I"$KAFL_INCLUDE" \
  -I"$SCRIPT_DIR" \
  main.cpp \
  -o "$OUT_DIR/ntgdi_fuzzer.exe" \
  -Wl,--subsystem,windows \
  -static -static-libgcc -static-libstdc++ \
  -luser32 -lgdi32 -lpsapi

echo "Built: $OUT_DIR/ntgdi_fuzzer.exe"
