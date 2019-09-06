/* -*- indent-tabs-mode: nil -*-
 *
 * plthook_win32.c -- implementation of plthook for PE format
 *
 * URL: https://github.com/kubo/plthook
 *
 * ------------------------------------------------------
 *
 * Copyright 2013-2014 Kubo Takehiro <kubo@jiubao.org>
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of the authors.
 *
 */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <windows.h>
#include <dbghelp.h>
#include "plthook.h"

#ifdef _MSC_VER
#pragma comment(lib, "dbghelp.lib")
#endif

#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif
#ifndef __GNUC__
#define __attribute__(arg)
#endif

#if defined _LP64 /* data model: I32/LP64 */
#define SIZE_T_FMT "lu"
#elif defined _WIN64  /* data model: IL32/P64 */
#define SIZE_T_FMT "I64u"
#else
#define SIZE_T_FMT "u"
#endif

#ifdef __CYGWIN__
#define stricmp strcasecmp
#endif

typedef struct {
    const char *mod_name;
    const char *name;
    void **addr;
} import_address_entry_t;

struct plthook {
    HMODULE hMod;
    unsigned int num_entries;
    import_address_entry_t entries[1];
};

static char errbuf[512];
static int plthook_open_real(plthook_t **plthook_out, HMODULE hMod);
static void set_errmsg(_Printf_format_string_ const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static void set_errmsg2(_Printf_format_string_ const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static const char *winsock2_ordinal2name(int ordinal);

int plthook_open(plthook_t **plthook_out, const char *filename)
{
    HMODULE hMod;

    *plthook_out = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, filename, &hMod)) {
        set_errmsg2("Cannot get module %s: ", filename);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    return plthook_open_real(plthook_out, hMod);
}

int plthook_open_by_handle(plthook_t **plthook_out, void *hndl)
{
    if (hndl == NULL) {
        set_errmsg("NULL handle");
        return PLTHOOK_FILE_NOT_FOUND;
    }
    return plthook_open_real(plthook_out, (HMODULE)hndl);
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
    HMODULE hMod;

    *plthook_out = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, address, &hMod)) {
        set_errmsg2("Cannot get module at address %p: ", address);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    return plthook_open_real(plthook_out, hMod);
}

static int plthook_open_real(plthook_t **plthook_out, HMODULE hMod)
{
    plthook_t *plthook;
    ULONG ulSize;
    IMAGE_IMPORT_DESCRIPTOR *desc_head, *desc;
    size_t num_entries = 0;
    size_t ordinal_name_buflen = 0;
    size_t idx;
    char *ordinal_name_buf;

    desc_head = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
    if (desc_head == NULL) {
        set_errmsg2("ImageDirectoryEntryToData error: ");
        return PLTHOOK_INTERNAL_ERROR;
    }

    /* Calculate size to allocate memory.  */
    for (desc = desc_head; desc->Name != 0; desc++) {
        IMAGE_THUNK_DATA *name_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *addr_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->FirstThunk);
        const char *module_name = (char *)hMod + desc->Name;
        int is_winsock2_dll = (stricmp(module_name, "WS2_32.DLL") == 0);

        while (addr_thunk->u1.Function != 0) {
            if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
                int ordinal = IMAGE_ORDINAL(name_thunk->u1.Ordinal);
                const char *name = NULL;
                if (is_winsock2_dll) {
                    name = winsock2_ordinal2name(ordinal);
                }
                if (name == NULL) {
#ifdef __CYGWIN__
                    ordinal_name_buflen += snprintf(NULL, 0, "%s:@%d", module_name, ordinal) + 1;
#else
                    ordinal_name_buflen += _scprintf("%s:@%d", module_name, ordinal) + 1;
#endif
                }
            }
            num_entries++;
            name_thunk++;
            addr_thunk++;
        }
    }

    plthook = calloc(1, offsetof(plthook_t, entries) + sizeof(import_address_entry_t) * num_entries + ordinal_name_buflen);
    if (plthook == NULL) {
        set_errmsg("failed to allocate memory: %" SIZE_T_FMT " bytes", sizeof(plthook_t));
        return PLTHOOK_OUT_OF_MEMORY;
    }
    plthook->hMod = hMod;
    plthook->num_entries = num_entries;

    ordinal_name_buf = (char*)plthook + offsetof(plthook_t, entries) + sizeof(import_address_entry_t) * num_entries;
    idx = 0;
    for (desc = desc_head; desc->Name != 0; desc++) {
        IMAGE_THUNK_DATA *name_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *addr_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->FirstThunk);
        const char *module_name = (char *)hMod + desc->Name;
        int is_winsock2_dll = (stricmp(module_name, "WS2_32.DLL") == 0);

        while (addr_thunk->u1.Function != 0) {
            const char *name = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
                int ordinal = IMAGE_ORDINAL(name_thunk->u1.Ordinal);
                if (is_winsock2_dll) {
                    name = winsock2_ordinal2name(ordinal);
                }
                if (name == NULL) {
                    name = ordinal_name_buf;
                    ordinal_name_buf += sprintf(ordinal_name_buf, "%s:@%d", module_name, ordinal) + 1;
                }
            } else {
                name = (char*)((PIMAGE_IMPORT_BY_NAME)((char*)hMod + name_thunk->u1.AddressOfData))->Name;
            }
            plthook->entries[idx].mod_name = module_name;
            plthook->entries[idx].name = name;
            plthook->entries[idx].addr = (void**)&addr_thunk->u1.Function;
            idx++;
            name_thunk++;
            addr_thunk++;
        }
    }

    *plthook_out = plthook;
    return 0;
}

int plthook_enum(plthook_t *plthook, unsigned int *pos, const char **name_out, void ***addr_out)
{
    if (*pos >= plthook->num_entries) {
        *name_out = NULL;
        *addr_out = NULL;
        return EOF;
    }
    *name_out = plthook->entries[*pos].name;
    *addr_out = plthook->entries[*pos].addr;
    (*pos)++;
    return 0;
}

static void replace_funcaddr(void **addr, void *newfunc, void **oldfunc)
{
    DWORD dwOld;
    DWORD dwDummy;

    if (oldfunc != NULL) {
        *oldfunc = *addr;
    }
    VirtualProtect(addr, sizeof(void *), PAGE_EXECUTE_READWRITE, &dwOld);
    *addr = newfunc;
    VirtualProtect(addr, sizeof(void *), dwOld, &dwDummy);
}

int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc)
{
#ifndef _WIN64
    size_t funcnamelen = strlen(funcname);
#endif
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int rv;
    BOOL import_by_ordinal = funcname[0] != '?' && strstr(funcname, ":@") != NULL;

    if (plthook == NULL) {
        set_errmsg("invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }
    while ((rv = plthook_enum(plthook, &pos, &name, &addr)) == 0) {
        if (import_by_ordinal) {
            if (stricmp(name, funcname) == 0) {
                goto found;
            }
        } else {
            /* import by name */
#ifdef _WIN64
            if (strcmp(name, funcname) == 0) {
                goto found;
            }
#else
            /* Function names may be decorated in Windows 32-bit applications. */
            if (strncmp(name, funcname, funcnamelen) == 0) {
                if (name[funcnamelen] == '\0' || name[funcnamelen] == '@') {
                    goto found;
                }
            }
            if (name[0] == '_' || name[0] == '@') {
                name++;
                if (strncmp(name, funcname, funcnamelen) == 0) {
                    if (name[funcnamelen] == '\0' || name[funcnamelen] == '@') {
                        goto found;
                    }
                }
            }
#endif
        }
    }
    if (rv == EOF) {
        set_errmsg("no such function: %s", funcname);
        rv = PLTHOOK_FUNCTION_NOT_FOUND;
    }
    return rv;
found:
    replace_funcaddr(addr, funcaddr, oldfunc);
    return 0;
}

void plthook_close(plthook_t *plthook)
{
    if (plthook != NULL) {
        free(plthook);
    }
}

const char *plthook_error(void)
{
    return errbuf;
}

static void set_errmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, sizeof(errbuf) - 1, fmt, ap);
    va_end(ap);
}

static void set_errmsg2(const char *fmt, ...)
{
    va_list ap;
    size_t len;

    va_start(ap, fmt);
    vsnprintf(errbuf, sizeof(errbuf) - 1, fmt, ap);
    va_end(ap);
    len = strlen(errbuf);
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   errbuf + len, sizeof(errbuf) - len - 1, NULL);
}

static const char *winsock2_ordinal2name(int ordinal)
{
    switch (ordinal) {
    case 1: return "accept";
    case 2: return "bind";
    case 3: return "closesocket";
    case 4: return "connect";
    case 5: return "getpeername";
    case 6: return "getsockname";
    case 7: return "getsockopt";
    case 8: return "htonl";
    case 9: return "htons";
    case 10: return "inet_addr";
    case 11: return "inet_ntoa";
    case 12: return "ioctlsocket";
    case 13: return "listen";
    case 14: return "ntohl";
    case 15: return "ntohs";
    case 16: return "recv";
    case 17: return "recvfrom";
    case 18: return "select";
    case 19: return "send";
    case 20: return "sendto";
    case 21: return "setsockopt";
    case 22: return "shutdown";
    case 23: return "socket";
    case 24: return "MigrateWinsockConfiguration";
    case 51: return "gethostbyaddr";
    case 52: return "gethostbyname";
    case 53: return "getprotobyname";
    case 54: return "getprotobynumber";
    case 55: return "getservbyname";
    case 56: return "getservbyport";
    case 57: return "gethostname";
    case 101: return "WSAAsyncSelect";
    case 102: return "WSAAsyncGetHostByAddr";
    case 103: return "WSAAsyncGetHostByName";
    case 104: return "WSAAsyncGetProtoByNumber";
    case 105: return "WSAAsyncGetProtoByName";
    case 106: return "WSAAsyncGetServByPort";
    case 107: return "WSAAsyncGetServByName";
    case 108: return "WSACancelAsyncRequest";
    case 109: return "WSASetBlockingHook";
    case 110: return "WSAUnhookBlockingHook";
    case 111: return "WSAGetLastError";
    case 112: return "WSASetLastError";
    case 113: return "WSACancelBlockingCall";
    case 114: return "WSAIsBlocking";
    case 115: return "WSAStartup";
    case 116: return "WSACleanup";
    case 151: return "__WSAFDIsSet";
    case 500: return "WEP";
    case 1000: return "WSApSetPostRoutine";
    case 1001: return "WsControl";
    case 1002: return "closesockinfo";
    case 1003: return "Arecv";
    case 1004: return "Asend";
    case 1005: return "WSHEnumProtocols";
    case 1100: return "inet_network";
    case 1101: return "getnetbyname";
    case 1102: return "rcmd";
    case 1103: return "rexec";
    case 1104: return "rresvport";
    case 1105: return "sethostname";
    case 1106: return "dn_expand";
    case 1107: return "WSARecvEx";
    case 1108: return "s_perror";
    case 1109: return "GetAddressByNameA";
    case 1110: return "GetAddressByNameW";
    case 1111: return "EnumProtocolsA";
    case 1112: return "EnumProtocolsW";
    case 1113: return "GetTypeByNameA";
    case 1114: return "GetTypeByNameW";
    case 1115: return "GetNameByTypeA";
    case 1116: return "GetNameByTypeW";
    case 1117: return "SetServiceA";
    case 1118: return "SetServiceW";
    case 1119: return "GetServiceA";
    case 1120: return "GetServiceW";
    case 1130: return "NPLoadNameSpaces";
    case 1131: return "NSPStartup";
    case 1140: return "TransmitFile";
    case 1141: return "AcceptEx";
    case 1142: return "GetAcceptExSockaddrs";
    }
    return NULL;
}
