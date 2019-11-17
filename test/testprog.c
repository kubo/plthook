#include <plthook.h>
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

#define CHK_PH(func) do { \
    if (func != 0) { \
        fprintf(stderr, "%s error: %s\n", #func, plthook_error()); \
        exit(1); \
    } \
} while (0)

typedef struct {
    const char *name;
    int enumerated;
} enum_test_data_t;

enum open_mode {
    OPEN_MODE_DEFAULT,
    OPEN_MODE_BY_HANDLE,
    OPEN_MODE_BY_ADDRESS,
};

static enum_test_data_t funcs_called_by_libtest[] = {
#if defined __APPLE__ && defined __LP64__
    {"_strtod", 0},
#elif defined __APPLE__ && !defined __LP64__
    {"_strtod$UNIX2003", 0},
#else
    {"strtod", 0},
#endif
    {NULL, },
};

static enum_test_data_t funcs_called_by_main[] = {
#if defined _WIN64 || (defined __CYGWIN__ && defined __x86_64__)
    {"strtod_cdecl", 0},
    {"strtod_stdcall", 0},
    {"strtod_fastcall", 0},
#ifndef __CYGWIN__
    {"libtest.dll:@10", 0},
#endif
#elif defined _WIN32 && defined __GNUC__
    {"strtod_cdecl", 0},
    {"strtod_stdcall@8", 0},
    {"@strtod_fastcall@8", 0},
#elif defined _WIN32 && !defined __GNUC__
    {"strtod_cdecl", 0},
    {"_strtod_stdcall@8", 0},
    {"@strtod_fastcall@8", 0},
    {"libtest.dll:@10", 0},
#elif defined __APPLE__
    {"_strtod_cdecl", 0},
#else
    {"strtod_cdecl", 0},
#endif
    {NULL, },
};

#define STRTOD_STR_SIZE 30

typedef struct {
    char str[STRTOD_STR_SIZE];
    double result;
} hooked_val_t;

/* value captured by hook from executable to libtest. */
static hooked_val_t val_exe2lib;
/* value captured by hook from libtest to libc. */
static hooked_val_t val_lib2libc;

static void reset_result(void)
{
    val_exe2lib.str[0] = '\0';
    val_exe2lib.result = 0.0;
    val_lib2libc.str[0] = '\0';
    val_lib2libc.result = 0.0;
}

static void set_result(hooked_val_t *hv, const char *str, double result)
{
    strncpy(hv->str, str, sizeof(hv->str));
    hv->result = result;
}

static void check_result(const char *str, double result, double expected_result, long line)
{
    if (result != expected_result) {
        goto error;
    }
    if (strcmp(val_exe2lib.str, str) != 0) {
        goto error;
    }
    if (val_exe2lib.result != result) {
        goto error;
    }
    if (strcmp(val_lib2libc.str, str) != 0) {
        goto error;
    }
    if (val_lib2libc.result != result) {
        goto error;
    }
    return;
error:
    fprintf(stderr,
            "Error: ['%s', %f, %f] ['%s', %f] ['%s', %f] at line %ld\n",
            str, result, expected_result,
            val_exe2lib.str, val_exe2lib.result,
            val_lib2libc.str, val_lib2libc.result,
            line);
    exit(1);
}

#define CHK_RESULT(func_name, str, expected_result) do { \
    double result__; \
    reset_result(); \
    result__ = func_name(str, NULL); \
    check_result(str, result__, expected_result, __LINE__); \
} while (0)

static double (*strtod_cdecl_old_func)(const char *, char**);
#if defined _WIN32 || defined __CYGWIN__
static double (__stdcall *strtod_stdcall_old_func)(const char *, char**);
static double (__fastcall *strtod_fastcall_old_func)(const char *, char**);
#endif
#if defined _WIN32
static double (*strtod_export_by_ordinal_old_func)(const char *, char**);
#endif

/* hook func from libtest to libc. */
static double strtod_hook_func(const char *str, char **endptr)
{
    double result = strtod(str, endptr);
    set_result(&val_lib2libc, str, result);
    return result;
}

/* hook func from testprog to libtest. */
static double strtod_cdecl_hook_func(const char *str, char **endptr)
{
    double result = strtod_cdecl_old_func(str, endptr);
    set_result(&val_exe2lib, str, result);
    return result;
}

#if defined _WIN32 || defined __CYGWIN__
/* hook func from testprog to libtest. */
static double __stdcall strtod_stdcall_hook_func(const char *str, char **endptr)
{
    double result = strtod_stdcall_old_func(str, endptr);
    set_result(&val_exe2lib, str, result);
    return result;
}

/* hook func from testprog to libtest. */
static double __fastcall strtod_fastcall_hook_func(const char *str, char **endptr)
{
    double result = strtod_fastcall_old_func(str, endptr);
    set_result(&val_exe2lib, str, result);
    return result;
}
#endif

#if defined _WIN32
/* hook func from testprog to libtest. */
static double strtod_export_by_ordinal_hook_func(const char *str, char **endptr)
{
    double result = strtod_export_by_ordinal_old_func(str, endptr);
    set_result(&val_exe2lib, str, result);
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
        for (i = 0; test_data[i].name != NULL; i++) {
            if (strcmp(test_data[i].name, name) == 0) {
                test_data[i].enumerated = 1;
            }
        }
    }
    for (i = 0; test_data[i].name != NULL; i++) {
        if (!test_data[i].enumerated) {
            fprintf(stderr, "%s is not enumerated by plthook_enum.\n", test_data[i].name);
            pos = 0;
            while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
                printf("   %s\n", name);
            }
            exit(1);
        }
    }
}

static void show_usage(const char *arg0)
{
    fprintf(stderr, "Usage: %s (open | open_by_handle)\n", arg0);
}

static void hook_function_calls_in_executable(enum open_mode open_mode)
{
    plthook_t *plthook;
    void *handle;

    switch (open_mode) {
    case OPEN_MODE_DEFAULT:
        CHK_PH(plthook_open(&plthook, NULL));
        break;
    case OPEN_MODE_BY_HANDLE:
#ifdef WIN32
        handle = GetModuleHandle(NULL);
#else
        handle = dlopen(NULL, RTLD_LAZY);
#endif
        assert(handle != NULL);
        CHK_PH(plthook_open_by_handle(&plthook, handle));
        break;
    case OPEN_MODE_BY_ADDRESS:
        CHK_PH(plthook_open_by_address(&plthook, &show_usage));
        break;
    }
    test_plthook_enum(plthook, funcs_called_by_main);
    CHK_PH(plthook_replace(plthook, "strtod_cdecl", (void*)strtod_cdecl_hook_func, (void**)&strtod_cdecl_old_func));
#if defined _WIN32 || defined __CYGWIN__
    CHK_PH(plthook_replace(plthook, "strtod_stdcall", (void*)strtod_stdcall_hook_func, (void**)&strtod_stdcall_old_func));
    CHK_PH(plthook_replace(plthook, "strtod_fastcall", (void*)strtod_fastcall_hook_func, (void**)&strtod_fastcall_old_func));
#endif
#if defined _WIN32
    CHK_PH(plthook_replace(plthook, "libtest.dll:@10", (void*)strtod_export_by_ordinal_hook_func, (void**)&strtod_export_by_ordinal_old_func));
#endif
    plthook_close(plthook);
}

static void hook_function_calls_in_library(enum open_mode open_mode)
{
    plthook_t *plthook;
    void *handle;
#if defined _WIN32 || defined __CYGWIN__
    const char *filename = "libtest.dll";
#else
    const char *filename = "libtest.so";
#endif
#ifndef WIN32
    void *address;
#endif

    switch (open_mode) {
    case OPEN_MODE_DEFAULT:
        CHK_PH(plthook_open(&plthook, filename));
        break;
    case OPEN_MODE_BY_HANDLE:
#ifdef WIN32
        handle = GetModuleHandle(filename);
#else
        handle = dlopen(filename, RTLD_LAZY | RTLD_NOLOAD);
#endif
        assert(handle != NULL);
        CHK_PH(plthook_open_by_handle(&plthook, handle));
        break;
    case OPEN_MODE_BY_ADDRESS:
#ifdef WIN32
        handle = GetModuleHandle(filename);
        assert(handle != NULL);
        CHK_PH(plthook_open_by_address(&plthook, handle));
#else
        handle = dlopen(filename, RTLD_LAZY | RTLD_NOLOAD);
        address = dlsym(handle, "strtod_cdecl");
        assert(address != NULL);
        CHK_PH(plthook_open_by_address(&plthook, (char*)address));
#endif
        break;
    }
    test_plthook_enum(plthook, funcs_called_by_libtest);
    CHK_PH(plthook_replace(plthook, "strtod", (void*)strtod_hook_func, NULL));
    plthook_close(plthook);
}

int main(int argc, char **argv)
{
    double expected_result = strtod("3.7", NULL);
    enum open_mode open_mode;

    if (argc != 2) {
        show_usage(argv[0]);
        exit(1);
    }
    if (strcmp(argv[1], "open") == 0) {
        open_mode = OPEN_MODE_DEFAULT;
    } else if (strcmp(argv[1], "open_by_handle") == 0) {
        open_mode = OPEN_MODE_BY_HANDLE;
    } else if (strcmp(argv[1], "open_by_address") == 0) {
        open_mode = OPEN_MODE_BY_ADDRESS;
    } else {
        show_usage(argv[0]);
        exit(1);
    }

    /* Resolve the function addreses by lazy binding. */
    strtod_cdecl("3.7", NULL);
#if defined _WIN32 || defined __CYGWIN__
    strtod_stdcall("3.7", NULL);
    strtod_fastcall("3.7", NULL);
#endif
#if defined _WIN32
    strtod_export_by_ordinal("3.7", NULL);
#endif

    hook_function_calls_in_executable(open_mode);
    hook_function_calls_in_library(open_mode);

    CHK_RESULT(strtod_cdecl, "3.7", expected_result);
#if defined _WIN32 || defined __CYGWIN__
    CHK_RESULT(strtod_stdcall, "3.7", expected_result);
    CHK_RESULT(strtod_fastcall, "3.7", expected_result);
#endif
#if defined _WIN32
    CHK_RESULT(strtod_export_by_ordinal, "3.7", expected_result);
#endif

    printf("success\n");
    return 0;
}
