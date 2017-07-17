PLTHook
=======

[![Build Status](https://travis-ci.org/kubo/plthook.svg?branch=master)](https://travis-ci.org/kubo/plthook) [![Build status](https://ci.appveyor.com/api/projects/status/ujqcdk9dcfpp809g/branch/master?svg=true)](https://ci.appveyor.com/project/kubo/plthook/branch/master)

What is plthook.
----------------

A utility library to hook library function calls issued by
specified object files (executable and libraries). This modifies
PLT (Procedure Linkage Table) entries in ELF format used on most Unixes
or [IAT (Import Address Table)][IAT] entries in PE format used on Windows.

[IAT]: https://en.wikipedia.org/wiki/Portable_Executable#Import_Table

Usage
-----

If you have a library `libfoo.so.1` and want to intercept
a function call `recv()` without modifying the library,
put `plthook.h` and `plthook_elf.c`, `plthook_win32.c` or `plthook_osx.c`
in your source tree and add the following code.

```c
/* This function is called instead of recv() called by libfoo.so.1  */
static ssize_t my_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t rv;
    
    ... do your task: logging, etc. ...
    rv = recv(sockfd, buf, len, flags); /* call real recv(). */
    ... do your task: logging, check received data, etc. ...
    return rv;
}
    
int install_hook_function()
{
    plthook_t *plthook;
    
    if (plthook_open(&plthook, "libfoo.so.1") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return -1;
    }
    if (plthook_replace(plthook, "recv", (void*)my_recv, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return -1;
    }
    plthook_close(plthook);
    return 0;
}
```

Another Usage
-------------

PLTHook provides a function enumerating PLT/IAT entries.

```c
void print_plt_entries(const char *filename)
{
    plthook_t *plthook;
    unsigned int pos = 0; /* This must be initialized with zero. */
    const char *name;
    void **addr;

    if (plthook_open(&plthook, filename) != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return -1;
    }
    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        printf("%p(%p) %s\n", addr, *addr, name);
    }
    plthook_close(plthook);
    return 0;
}
```

Supported Platforms
-------------------

| Platform | source file |
| -------- | ----------- |
| Linux i386 and x86_64 | plthook_elf.c |
| Linux arm, aarch64, powerpc and powerpc64le (*1) | plthook_elf.c |
| Windows 32-bit and x64 (MSVC, Mingw32 and Cygwin) | plthook_win32.c |
| macOS | plthook_osx.c
| Solaris x86_64 | plthook_elf.c |
| FreeBSD i386 and x86_64 except i386 program on x86_64 OS | plthook_elf.c |

*1 These are tested on [QEMU][], which version must be 2.2 or later, user-mode emulation.

IMO, unix-like platforms except AIX and HP-UX pa-risc(32bit) could be supported
by `plthook_elf.c` with small modification as long as the object file format
is [ELF][].

[QEMU]: http://www.qemu.org/
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

License
-------

2-clause BSD-style license.
