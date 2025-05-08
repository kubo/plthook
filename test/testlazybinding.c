#include "libtest.h"
#include <stddef.h>
double lazy_binding_call()
{
    double num = strtod_cdecl("3.7", NULL);
    return num;
}