#ifndef WINDOWS_SYSCALL_FUZZER_PARSER_PRELUDE_H
#define WINDOWS_SYSCALL_FUZZER_PARSER_PRELUDE_H

/*
 * Keep windows.h from pulling in unnecessary user-interface and networking
 * declarations. We only need the fundamental Windows type environment here.
 */
#define WIN32_LEAN_AND_MEAN

/*
 * Provides declarations/macros used by legacy DirectDraw headers, including
 * GUID and DEFINE_GUID.
 */
#include <windows.h>
#include <guiddef.h>

/*
 * Some old SDK-style headers use these architecture macros.
 */
#ifndef _WIN64
# define _WIN64 1
#endif

#ifndef _AMD64_
# define _AMD64_ 1
#endif

#ifndef _M_AMD64
# define _M_AMD64 100
#endif

#ifndef _M_X64
# define _M_X64 100
#endif

#endif