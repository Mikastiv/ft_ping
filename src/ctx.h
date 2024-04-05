#pragma once

#ifdef __clang__
#define COMPILER_CLANG 1
#else
#ifdef _MSC_VER
#define COMPILER_CL 1
#endif
#endif

#ifdef __GNUC__
#define COMPILER_GCC 1
#endif

#ifdef __linux__
#define OS_LINUX 1
#endif

#ifdef __APPLE__
#define OS_MACOS 1
#endif

#ifdef _WIN32
#define OS_WINDOWS 1
#endif

#if COMPILER_CLANG || COMPILER_GCC
#ifdef __x86_64__
#define ARCH_X64 1
#endif
#endif

#if COMPILER_CL
#ifdef _M_AMD64
#define ARCH_X64 1
#endif
#endif
