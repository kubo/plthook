#ifndef LISTTEST_H
#define LISTTEST_H 1

#ifdef _WIN32
#ifdef LIBTEST_DLL
#define LIBTESTAPI __declspec(dllexport)
#else
#define LIBTESTAPI __declspec(dllimport)
#endif
#else
#define LIBTESTAPI
#endif

LIBTESTAPI
double ceil_cdecl(double x);

#if defined _WIN32 || defined __CYGWIN__
LIBTESTAPI
double __stdcall ceil_stdcall(double x);

LIBTESTAPI
double __fastcall ceil_fastcall(double x);
#endif

#endif
