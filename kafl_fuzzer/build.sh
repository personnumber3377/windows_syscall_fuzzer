#!/usr/bin/env bash
set -euo pipefail

CXX="${CXX:-x86_64-w64-mingw32-g++}"
KAFL_INCLUDE="${KAFL_INCLUDE:-../}"
OUT_DIR="${OUT_DIR:-build}"

mkdir -p "$OUT_DIR"

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
  -I"$KAFL_INCLUDE" \
  main.cpp \
  -o "$OUT_DIR/ntgdi_fuzzer.exe" \
  -Wl,--subsystem,windows \
  -luser32 -lgdi32 -lpsapi

echo "Built: $OUT_DIR/ntgdi_fuzzer.exe"
