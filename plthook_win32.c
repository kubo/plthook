/* -*- indent-tabs-mode: nil -*-
 *
 * Copyright 2013 Kubo Takehiro <kubo@jiubao.org>
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
#include <stdarg.h>
#include <windows.h>
#include <imagehlp.h>
#include "plthook.h"

#define DUMP_ENTRIES 0

#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif
#ifndef __GNUC__
#define __attribute__(arg)
#endif

static char errbuf[512];
static void set_errmsg(_Printf_format_string_ const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static void set_errmsg2(_Printf_format_string_ const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static const char *winsock2_ordinal2name(int ordinal);

int plthook_open(plthook_t **plthook_out, const char *filename)
{
    HMODULE hMod;

    *plthook_out = NULL;
    if (!GetModuleHandleExA(0, filename, &hMod)) {
        set_errmsg2("Cannot get module %s: ", filename);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    *plthook_out = (plthook_t*)hMod;
    return 0;
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
    HMODULE hMod;

    *plthook_out = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, address, &hMod)) {
        set_errmsg2("Cannot get module at address %p: ", address);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    *plthook_out = (plthook_t*)hMod;
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
    HMODULE hMod = (HMODULE)plthook;
    ULONG ulSize;
    IMAGE_IMPORT_DESCRIPTOR *desc;
    int target_ordinal = 0;

    if (plthook == NULL) {
        set_errmsg("Invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }

    if (funcname[0] == '@') {
        target_ordinal = atoi(funcname + 1);
    }

    desc = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

    if (desc == NULL) {
        set_errmsg2("ImageDirectoryEntryToData error: ");
        return PLTHOOK_INTERNAL_ERROR;
    }
    while (desc->Name != 0) {
        IMAGE_THUNK_DATA *name_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *addr_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->FirstThunk);
        int is_winsock2_dll = (stricmp((char *)hMod + desc->Name, "WS2_32.DLL") == 0);
#if DUMP_ENTRIES
        fprintf(stderr, "DLL: %s\n", (char *)hMod + desc->Name);
#endif
        while (addr_thunk->u1.Function != 0) {
            const char *name = NULL;
            int ordinal = -1;

            if (!IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
                name = (char*)((PIMAGE_IMPORT_BY_NAME)((char*)hMod + name_thunk->u1.AddressOfData))->Name;
            } else {
                ordinal = IMAGE_ORDINAL(name_thunk->u1.Ordinal);
                if (is_winsock2_dll) {
                    name = winsock2_ordinal2name(ordinal);
                }
            }
#if DUMP_ENTRIES
            if (name != NULL) {
                if (ordinal == -1) {
                    fprintf(stderr, "   %p %s\n", (void*)addr_thunk->u1.Function, name);
                } else {
                    fprintf(stderr, "   %p %s (@%d)\n", (void*)addr_thunk->u1.Function, name, ordinal);
                }
            } else {
                fprintf(stderr, "   %p @%d\n", (void*)addr_thunk->u1.Function, ordinal);
            }
#endif
            if (ordinal == target_ordinal || (name != NULL && strcmp(name, funcname) == 0)) {
                replace_funcaddr((void**)&addr_thunk->u1.Function, funcaddr, oldfunc);
                return 0;
            }
            name_thunk++;
            addr_thunk++;
        }
        desc++;
    }
    set_errmsg("No such function is imported: %s", funcname);
    return PLTHOOK_FUNCTION_NOT_FOUND;
}

void plthook_close(plthook_t *plthook)
{
    FreeLibrary((HMODULE)plthook);
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
