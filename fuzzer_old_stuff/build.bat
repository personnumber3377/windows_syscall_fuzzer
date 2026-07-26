@echo off
setlocal

rem Run from an x64 Visual Studio Developer Command Prompt.
rem generated_ntgdi_harness.cpp must be beside main.cpp.
rem It is #included by main.cpp, so do not pass it separately to cl.exe.

if not exist generated_ntgdi_harness.cpp (
    echo error: generated_ntgdi_harness.cpp was not found in %CD%
    exit /b 1
)

if not exist main.cpp (
    echo error: main.cpp was not found in %CD%
    exit /b 1
)

if not exist build mkdir build

cl.exe ^
  /nologo ^
  /std:c++17 ^
  /permissive- ^
  /W4 ^
  /EHsc ^
  /Zi ^
  /Od ^
  /Ob0 ^
  /GS ^
  /Oy- ^
  /DWIN32_LEAN_AND_MEAN ^
  /D_CRT_SECURE_NO_WARNINGS ^
  /Fe:build\ntgdi_fuzzer.exe ^
  /Fd:build\ntgdi_fuzzer.pdb ^
  /Fo:build\main.obj ^
  main.cpp ^
  /link ^
  /DEBUG:FULL ^
  /INCREMENTAL:NO ^
  /OPT:NOREF ^
  /OPT:NOICF ^
  user32.lib ^
  gdi32.lib

if errorlevel 1 (
    echo.
    echo Build failed.
    exit /b 1
)

echo.
echo Built: build\ntgdi_fuzzer.exe
echo PDB:   build\ntgdi_fuzzer.pdb
exit /b 0
