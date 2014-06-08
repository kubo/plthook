#include <math.h>
#include "libtest.h"

double ceil_cdecl(double x)
{
    return ceil(x);
}

#ifdef _WIN32
double __stdcall ceil_stdcall(double x)
{
    return ceil(x);
}

double __fastcall ceil_fastcall(double x)
{
    return ceil(x);
}
#endif
