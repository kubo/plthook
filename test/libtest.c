#include <stdlib.h>
#include "libtest.h"

double strtod_cdecl(const char *str, char **endptr)
{
    return strtod(str, endptr);
}

#if defined _WIN32 || defined __CYGWIN__
double __stdcall strtod_stdcall(const char *str, char **endptr)
{
    return strtod(str, endptr);
}

double __fastcall strtod_fastcall(const char *str, char **endptr)
{
    return strtod(str, endptr);
}

double strtod_export_by_ordinal(const char *str, char **endptr)
{
    return strtod(str, endptr);
}
#endif

#if defined __APPLE__
int atoi_dummy(const char *str)
{
    /* Just to avoid to put "strtod" at the beginning of GOT. */
    return atoi(str);
}
#endif
