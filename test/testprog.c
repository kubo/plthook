#include <plthook.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "libtest.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

typedef struct {
    const char *name;
    int enumerated;
} enum_test_data_t;

enum open_mode {
    OPEN_MODE_DEFAULT,
    OPEN_MODE_BY_HANDLE,
};

static enum_test_data_t funcs_called_by_libtest[] = {
#if defined __APPLE__
    {"_ceil", 0},
#else
    {"ceil", 0},
#endif
    {NULL, },
};

static enum_test_data_t funcs_called_by_main[] = {
#if defined _WIN64 || (defined __CYGWIN__ && defined __x86_64__)
    {"ceil_cdecl", 0},
    {"ceil_stdcall", 0},
    {"ceil_fastcall", 0},
#elif defined _WIN32 && defined __GNUC__
    {"ceil_cdecl", 0},
    {"ceil_stdcall@8", 0},
    {"@ceil_fastcall@8", 0},
#elif defined _WIN32 && !defined __GNUC__
    {"ceil_cdecl", 0},
    {"_ceil_stdcall@8", 0},
    {"@ceil_fastcall@8", 0},
#elif defined __APPLE__
    {"_ceil_cdecl", 0},
#else
    {"ceil_cdecl", 0},
#endif
    {NULL, },
};

static double ceil_arg = 0.0;
static double ceil_result = 0.0;
static double ceil_cdecl_arg = 0.0;
static double ceil_cdecl_result = 0.0;
#if defined _WIN32 || defined __CYGWIN__
static double ceil_stdcall_arg = 0.0;
static double ceil_stdcall_result = 0.0;
static double ceil_fastcall_arg = 0.0;
static double ceil_fastcall_result = 0.0;
#endif

static double (*ceil_cdecl_old_func)(double);
#if defined _WIN32 || defined __CYGWIN__
static double (__stdcall *ceil_stdcall_old_func)(double);
static double (__fastcall *ceil_fastcall_old_func)(double);
#endif

static double ceil_hook_func(double arg)
{
    double result = ceil(arg);
    ceil_arg = arg;
    ceil_result = result;
    return result;
}

static double ceil_cdecl_hook_func(double arg)
{
    double result = ceil_cdecl_old_func(arg);
    ceil_cdecl_arg = arg;
    ceil_cdecl_result = result;
    return result;
}

#if defined _WIN32 || defined __CYGWIN__
static double __stdcall ceil_stdcall_hook_func(double arg)
{
    double result = ceil_stdcall_old_func(arg);
    ceil_stdcall_arg = arg;
    ceil_stdcall_result = result;
    return result;
}

static double __fastcall ceil_fastcall_hook_func(double arg)
{
    double result = ceil_fastcall_old_func(arg);
    ceil_fastcall_arg = arg;
    ceil_fastcall_result = result;
    return result;
}
#endif

static void test_plthook_enum(plthook_t *plthook, enum_test_data_t *test_data)
{
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int i;

    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
#if 0
        printf("name = %s, address = %p at %p\n", name, *addr, addr);
#endif
	for (i = 0; test_data[i].name != NULL; i++) {
	    if (strcmp(test_data[i].name, name) == 0) {
	        test_data[i].enumerated = 1;
	    }
	}
    }
    for (i = 0; test_data[i].name != NULL; i++) {
        if (!test_data[i].enumerated) {
	    fprintf(stderr, "%s is not enumerated by plthook_enum.\n", test_data[i].name);
	    exit(1);
	}
    }
}

static void show_usage(const char *arg0)
{
    fprintf(stderr, "Usage: %s (open | open_by_handle)\n", arg0);
    exit(1);
}

int main(int argc, char **argv)
{
    plthook_t *plthook;
    double arg;
    double result;
    void *handle;
    enum open_mode open_mode;
#if defined _WIN32 || defined __CYGWIN__
    const char *filename = "libtest.dll";
#else
    const char *filename = "libtest.so";
#endif

    if (argc != 2) {
        show_usage(argv[0]);
    }
    if (strcmp(argv[1], "open") == 0) {
        open_mode = OPEN_MODE_DEFAULT;
    } else if (strcmp(argv[1], "open_by_handle") == 0) {
        open_mode = OPEN_MODE_BY_HANDLE;
    } else {
        show_usage(argv[0]);
    }

    /* Call ceil_cdecl(), ceil_stdcall() and ceil_fastcall() before plthook_replace()
     * to resolve the address by lazy binding.
     */
    arg = 1.3;
    ceil_cdecl(arg);
#if defined _WIN32 || defined __CYGWIN__
    ceil_stdcall(arg);
    ceil_fastcall(arg);
#endif
    /* ensure that *_result and *_arg are not changed. */
    assert(ceil_arg == 0.0);
    assert(ceil_result == 0.0);
    assert(ceil_cdecl_arg == 0.0);
    assert(ceil_cdecl_result == 0.0);
#if defined _WIN32 || defined __CYGWIN__
    assert(ceil_stdcall_arg == 0.0);
    assert(ceil_stdcall_result == 0.0);
    assert(ceil_fastcall_arg == 0.0);
    assert(ceil_fastcall_result == 0.0);
#endif

    switch (open_mode) {
    case OPEN_MODE_DEFAULT:
        assert(plthook_open(&plthook, NULL) == 0);
        break;
    case OPEN_MODE_BY_HANDLE:
#ifdef WIN32
        handle = GetModuleHandle(NULL);
#else
        handle = dlopen(NULL, RTLD_LAZY);
#endif
        assert(handle != NULL);
        assert(plthook_open_by_handle(&plthook, handle) == 0);
        break;
    }
    test_plthook_enum(plthook, funcs_called_by_main);
    assert(plthook_replace(plthook, "ceil_cdecl", (void*)ceil_cdecl_hook_func, (void**)&ceil_cdecl_old_func) == 0);
#if defined _WIN32 || defined __CYGWIN__
    assert(plthook_replace(plthook, "ceil_stdcall", (void*)ceil_stdcall_hook_func, (void**)&ceil_stdcall_old_func) == 0);
    assert(plthook_replace(plthook, "ceil_fastcall", (void*)ceil_fastcall_hook_func, (void**)&ceil_fastcall_old_func) == 0);
#endif
    plthook_close(plthook);


    switch (open_mode) {
    case OPEN_MODE_DEFAULT:
        assert(plthook_open(&plthook, filename) == 0);
        break;
    case OPEN_MODE_BY_HANDLE:
#ifdef WIN32
        handle = GetModuleHandle(filename);
#else
        handle = dlopen(filename, RTLD_LAZY | RTLD_NOLOAD);
#endif
        assert(handle != NULL);
        assert(plthook_open_by_handle(&plthook, handle) == 0);
        break;
    }

    test_plthook_enum(plthook, funcs_called_by_libtest);
    assert(plthook_replace(plthook, "ceil", (void*)ceil_hook_func, NULL) == 0);
    plthook_close(plthook);

    arg = 3.7;
    result = ceil_cdecl(arg);
    assert(result != 0.0);
    assert(ceil_cdecl_arg == arg);
    assert(ceil_cdecl_result == result);
    assert(ceil_result == result);
    assert(ceil_arg == arg);

#if defined _WIN32 || defined __CYGWIN__
    arg = 5.3;
    result = ceil_stdcall(arg);
    assert(result != 0.0);
    assert(ceil_stdcall_arg == arg);
    assert(ceil_stdcall_result == result);
    assert(ceil_result == result);
    assert(ceil_arg == arg);

    arg = 8.8;
    result = ceil_fastcall(arg);
    assert(result != 0.0);
    assert(ceil_fastcall_arg == arg);
    assert(ceil_fastcall_result == result);
    assert(ceil_result == result);
    assert(ceil_arg == arg);
#endif

    printf("success\n");
    return 0;
}
