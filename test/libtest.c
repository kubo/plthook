#include <math.h>
#include "libtest.h"

double ceil_cdecl(double x)
{
    return ceil(x);
}

#if defined _WIN32 || defined __CYGWIN__
double __stdcall ceil_stdcall(double x)
{
    return ceil(x);
}

double __fastcall ceil_fastcall(double x)
{
    return ceil(x);
}

double ceil_export_by_ordinal(double x)
{
    return ceil(x);
}
#endif
