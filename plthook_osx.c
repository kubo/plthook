/* -*- indent-tabs-mode: nil -*-
 *
 * plthook_osx.c -- implemention of plthook for OS X
 *
 * URL: https://github.com/kubo/plthook
 *
 * ------------------------------------------------------
 *
 * Copyright 2014 Kubo Takehiro <kubo@jiubao.org>
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
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include "plthook.h"

// #define PLTHOOK_DEBUG_CMD 1
// #define PLTHOOK_DEBUG_BIND 1

#ifdef PLTHOOK_DEBUG_CMD
#define DEBUG_CMD(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_CMD(...)
#endif

#ifdef PLTHOOK_DEBUG_BIND
#define DEBUG_BIND(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_BIND(...)
#endif

#ifdef __LP64__
#define segment_command_ segment_command_64
#else
#define segment_command_ segment_command
#endif

typedef struct {
    const char *name;
    void **addr;
} bind_address_t;

struct plthook {
    unsigned int num_entries;
    bind_address_t entries[1];
};

static int plthook_open_real(plthook_t **plthook_out, const struct mach_header *mh);
static unsigned int get_bind_addr(plthook_t *plthook, const uint8_t *base, uint32_t lazy_bind_off, uint32_t lazy_bind_size, struct segment_command_ **segments, int addrdiff);

static void set_errmsg(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static void set_bind_addr(unsigned int *idx, plthook_t *plthook, const uint8_t *base, const char *sym_name, int seg_index, int seg_offset, struct segment_command_ **segments);

static uint64_t uleb128(const uint8_t **p)
{
    uint64_t r = 0;
    int s = 0;
    do {
        r |= (uint64_t)(**p & 0x7f) << s;
        s += 7;
    } while (*(*p)++ >= 0x80);
    return r;
}

static int64_t sleb128(const uint8_t** p)
{
    int64_t r = 0;
    int s = 0;
    for (;;) {
        uint8_t b = *(*p)++;
        if (b < 0x80) {
          if (b & 0x40) {
            r -= (0x80 - b) << s;
          } else {
            r |= (b & 0x3f) << s;
          }
          break;
        }
        r |= (b & 0x7f) << s;
        s += 7;
    }
    return r;
}

static char errmsg[512];

int plthook_open(plthook_t **plthook_out, const char *filename)
{
    uint32_t idx = 0;

    if (filename != NULL) {
        size_t namelen = strlen(filename);

        while (1) {
            const char *image_name = _dyld_get_image_name(idx);
            size_t offset = 0;

            if (image_name == NULL) {
                *plthook_out = NULL;
                set_errmsg("Cannot find file: %s", filename);
                return PLTHOOK_FILE_NOT_FOUND;
            }
            if (*filename != '/') {
                size_t image_name_len = strlen(image_name);
                if (image_name_len > namelen) {
                    offset = image_name_len - namelen;
                }
            }
            if (strcmp(image_name + offset, filename) == 0) {
                break;
            }
            idx++;
        }
    }
    return plthook_open_real(plthook_out, _dyld_get_image_header(idx));
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
    Dl_info dlinfo;

    if (!dladdr(address, &dlinfo)) {
        *plthook_out = NULL;
        set_errmsg("Cannot find address: %p", address);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    return plthook_open_real(plthook_out, dlinfo.dli_fbase);
}

#define NUM_SEGMENTS 10

static int plthook_open_real(plthook_t **plthook_out, const struct mach_header *mh)
{
    struct load_command *cmd;
    const uint8_t *base = (const uint8_t *)mh;
    uint32_t lazy_bind_off = 0;
    uint32_t lazy_bind_size = 0;
    struct segment_command_ *segments[NUM_SEGMENTS];
    int segment_idx = 0;
    unsigned int nbind;
    int addrdiff = 0;
    int i;

    memset(segments, 0, sizeof(segments));
#ifdef __LP64__
    cmd = (struct load_command *)((size_t)mh + sizeof(struct mach_header_64));
#else
    cmd = (struct load_command *)((size_t)mh + sizeof(struct mach_header));
#endif
    for (i = 0; i < mh->ncmds; i++) {
        struct dyld_info_command *dyld_info;
        struct segment_command *segment;
        struct segment_command_64 *segment64;

        switch (cmd->cmd) {
        case LC_SEGMENT: /* 0x1 */
            segment = (struct segment_command *)cmd;
            DEBUG_CMD("LC_SEGMENT\n"
                      "  segname   %s\n"
                      "  vmaddr    %8x  vmsize     %8x\n"
                      "  fileoff   %8x  filesize   %8x\n"
                      "  maxprot   %8x  initprot   %8x\n"
                      "  nsects    %8d  flags      %8x\n",
                      segment->segname,
                      segment->vmaddr, segment->vmsize,
                      segment->fileoff, segment->filesize,
                      segment->maxprot, segment->initprot,
                      segment->nsects, segment->flags);
            if (strcmp(segment->segname, "__LINKEDIT") == 0) {
                addrdiff = segment->vmaddr - segment->fileoff;
            }
#ifndef __LP64__
            segments[segment_idx++] = segment;
#endif
            break;
        case LC_SEGMENT_64: /* 0x19 */
            segment64 = (struct segment_command_64 *)cmd;
            DEBUG_CMD("LC_SEGMENT_64\n"
                      "  segname   %s\n"
                      "  vmaddr    %8llx  vmsize     %8llx\n"
                      "  fileoff   %8llx  filesize   %8llx\n"
                      "  maxprot   %8x  initprot   %8x\n"
                      "  nsects    %8d  flags      %8x\n",
                      segment64->segname,
                      segment64->vmaddr, segment64->vmsize,
                      segment64->fileoff, segment64->filesize,
                      segment64->maxprot, segment64->initprot,
                      segment64->nsects, segment64->flags);
            if (strcmp(segment64->segname, "__LINKEDIT") == 0) {
                addrdiff = segment64->vmaddr - segment64->fileoff;
            }
#ifdef __LP64__
            segments[segment_idx++] = segment64;
#endif
            break;
        case LC_DYLD_INFO_ONLY: /* (0x22|LC_REQ_DYLD) */
            dyld_info= (struct dyld_info_command *)cmd;
            lazy_bind_off = dyld_info->lazy_bind_off;
            lazy_bind_size = dyld_info->lazy_bind_size;
            DEBUG_CMD("LC_DYLD_INFO_ONLY\n"
                      "                 offset     size\n"
                      "  rebase       %8x %8x\n"
                      "  bind         %8x %8x\n"
                      "  weak_bind    %8x %8x\n"
                      "  lazy_bind    %8x %8x\n"
                      "  export_bind  %8x %8x\n",
                      dyld_info->rebase_off, dyld_info->rebase_size,
                      dyld_info->bind_off, dyld_info->bind_size,
                      dyld_info->weak_bind_off, dyld_info->weak_bind_size,
                      dyld_info->lazy_bind_off, dyld_info->lazy_bind_size,
                      dyld_info->export_off, dyld_info->export_size);
            break;
        case LC_SYMTAB: /* 0x2 */
            DEBUG_CMD("LC_SYMTAB\n");
            break;
        case LC_DYSYMTAB: /* 0xb */
            DEBUG_CMD("LC_DYSYMTAB\n");
            break;
        case LC_LOAD_DYLIB: /* 0xc */
            DEBUG_CMD("LC_LOAD_DYLIB\n");
            break;
        case LC_ID_DYLIB: /* 0xd */
            DEBUG_CMD("LC_ID_DYLIB\n");
            break;
        case LC_LOAD_DYLINKER: /* 0xe */
            DEBUG_CMD("LC_LOAD_DYLINKER\n");
            break;
        case LC_ROUTINES_64: /* 0x1a */
            DEBUG_CMD("LC_ROUTINES_64\n");
            break;
        case LC_UUID: /* 0x1b */
            DEBUG_CMD("LC_UUID\n");
            break;
        case LC_VERSION_MIN_MACOSX: /* 0x24 */
            DEBUG_CMD("LC_VERSION_MIN_MACOSX\n");
            break;
        case LC_FUNCTION_STARTS: /* 0x26 */
            DEBUG_CMD("LC_FUNCTION_STARTS\n");
            break;
        case LC_MAIN: /* 0x28|LC_REQ_DYLD */
            DEBUG_CMD("LC_MAIN\n");
            break;
        case LC_DATA_IN_CODE: /* 0x29 */
            DEBUG_CMD("LC_DATA_IN_CODE\n");
            break;
        case LC_SOURCE_VERSION: /* 0x2A */
            DEBUG_CMD("LC_SOURCE_VERSION\n");
            break;
        case LC_DYLIB_CODE_SIGN_DRS: /* 0x2B */
            DEBUG_CMD("LC_DYLIB_CODE_SIGN_DRS\n");
            break;
        default:
            DEBUG_CMD("LC_? (0x%x)\n", cmd->cmd);
        }
        cmd = (struct load_command *)((size_t)cmd + cmd->cmdsize);
    }
    nbind = get_bind_addr(NULL, base, lazy_bind_off, lazy_bind_size, segments, addrdiff);
    *plthook_out = (plthook_t*)malloc(offsetof(plthook_t, entries) + sizeof(bind_address_t) * nbind);
    (*plthook_out)->num_entries = nbind;
    get_bind_addr(*plthook_out, base, lazy_bind_off, lazy_bind_size, segments, addrdiff);

    return 0;
}

static unsigned int get_bind_addr(plthook_t *plthook, const uint8_t *base, uint32_t lazy_bind_off, uint32_t lazy_bind_size, struct segment_command_ **segments, int addrdiff)
{
    const uint8_t *ptr = base + lazy_bind_off + addrdiff;
    const uint8_t *end = ptr + lazy_bind_size;
    const char *sym_name;
    int seg_index = 0;
    uint64_t seg_offset = 0;
    int count, skip;
    unsigned int idx;
    DEBUG_BIND("get_bind_addr(%p, 0x%x, 0x%x", base, lazy_bind_off, lazy_bind_size);
    for (idx = 0; segments[idx] != NULL; idx++) {
        DEBUG_BIND(", [%s]", segments[idx]->segname);
    }
    DEBUG_BIND(")\n");

    idx = 0;
    while (ptr < end) {
        uint8_t op = *ptr & BIND_OPCODE_MASK;
        uint8_t imm = *ptr & BIND_IMMEDIATE_MASK;
        uint64_t ulebval;
        int64_t slebval;
        int i;

        DEBUG_BIND("0x%02x: ", *ptr);
        ptr++;
        switch (op) {
        case BIND_OPCODE_DONE:
            DEBUG_BIND("BIND_OPCODE_DONE\n");
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            DEBUG_BIND("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: ordinal = %u\n", imm);
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            ulebval = uleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: ordinal = %llu\n", ulebval);
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (imm == 0) {
                DEBUG_BIND("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = 0\n");
            } else {
                DEBUG_BIND("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = %u\n", BIND_OPCODE_MASK | imm);
            }
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char*)ptr;
            ptr += strlen(sym_name) + 1;
            DEBUG_BIND("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: sym_name = %s\n", sym_name);
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            DEBUG_BIND("BIND_OPCODE_SET_TYPE_IMM: type = %u\n", imm);
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            slebval = sleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_SET_ADDEND_SLEB: ordinal = %lld\n", slebval);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = uleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: seg_index = %u, seg_offset = 0x%llx\n", seg_index, seg_offset);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_ADD_ADDR_ULEB: seg_offset = 0x%llx\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND:
            set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
            DEBUG_BIND("BIND_OPCODE_DO_BIND\n");
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: seg_offset = 0x%llx\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
            seg_offset += imm * sizeof(void *);
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = uleb128(&ptr);
            skip = uleb128(&ptr);
            for (i = 0; i < count; i++) {
                set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
                seg_offset += skip;
            }
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");
            break;
        }
    }
    return idx;
}

static void set_bind_addr(unsigned int *idx, plthook_t *plthook, const uint8_t *base, const char *sym_name, int seg_index, int seg_offset, struct segment_command_ **segments)
{
    if (plthook != NULL) {
        uint32_t vmaddr = segments[seg_index]->vmaddr;
        plthook->entries[*idx].name = sym_name;
        plthook->entries[*idx].addr = (void**)(base + vmaddr + seg_offset);
    }
    (*idx)++;
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

int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc)
{
    size_t funcnamelen = strlen(funcname);
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int rv;

    if (plthook == NULL) {
        set_errmsg("invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }
    while ((rv = plthook_enum(plthook, &pos, &name, &addr)) == 0) {
        if (strncmp(name, funcname, funcnamelen) == 0) {
            if (name[funcnamelen] == '\0' || name[funcnamelen] == '$') {
                goto matched;
            }
        }
        if (name[0] == '@') {
            /* Oracle libclntsh.dylib imports 'read' as '@_read'. */
            name++;
            if (strncmp(name, funcname, funcnamelen) == 0) {
                if (name[funcnamelen] == '\0' || name[funcnamelen] == '$') {
                    goto matched;
                }
            }
        }
        if (name[0] == '_') {
            name++;
            if (strncmp(name, funcname, funcnamelen) == 0) {
                if (name[funcnamelen] == '\0' || name[funcnamelen] == '$') {
                    goto matched;
                }
            }
        }
        continue;
matched:
        if (oldfunc) {
            *oldfunc = *addr;
        }
        *addr = funcaddr;
        return 0;
    }
    if (rv == EOF) {
        set_errmsg("no such function: %s", funcname);
        rv = PLTHOOK_FUNCTION_NOT_FOUND;
    }
    return rv;
}

void plthook_close(plthook_t *plthook)
{
    if (plthook != NULL) {
        free(plthook);
    }
    return;
}

const char *plthook_error(void)
{
    return errmsg;
}

static void set_errmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg, sizeof(errmsg) - 1, fmt, ap);
    va_end(ap);
}
