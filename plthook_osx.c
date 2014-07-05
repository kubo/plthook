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

// #define PLTHOOK_DEBUG 1

#ifdef PLTHOOK_DEBUG
#define DEBUG_(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_(...)
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
static unsigned int get_bind_addr(plthook_t *plthook, const uint8_t *base, uint32_t lazy_bind_off, uint32_t lazy_bind_size, struct segment_command **segments);

static void set_errmsg(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));
static void set_bind_addr(unsigned int *idx, plthook_t *plthook, const uint8_t *base, const char *sym_name, int seg_index, int seg_offset, struct segment_command **segments);

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
    struct segment_command *segments[NUM_SEGMENTS];
    int segment_idx = 0;
    unsigned int nbind;
    int i;

#ifdef __LP64__
    cmd = (struct load_command *)((size_t)mh + sizeof(struct mach_header_64));
#else
    cmd = (struct load_command *)((size_t)mh + sizeof(struct mach_header));
#endif
    for (i = 0; i < mh->ncmds; i++) {
        struct dyld_info_command *dyld_info;

        switch (cmd->cmd) {
#ifdef __LP64__
        case LC_SEGMENT_64: /* 0x19 */
            DEBUG_("LC_SEGMENT_64\n");
#else
        case LC_SEGMENT: /* 0x1 */
            DEBUG_("LC_SEGMENT\n");
#endif
            segments[segment_idx++] = (struct segment_command *)cmd;
            break;
        case LC_DYLD_INFO_ONLY: /* (0x22|LC_REQ_DYLD) */
            DEBUG_("LC_DYLD_INFO_ONLY\n");
            dyld_info= (struct dyld_info_command *)cmd;
            lazy_bind_off = dyld_info->lazy_bind_off;
            lazy_bind_size = dyld_info->lazy_bind_size;
            break;
        case LC_SYMTAB: /* 0x2 */
            DEBUG_("LC_SYMTAB\n");
            break;
        case LC_DYSYMTAB: /* 0xb */
            DEBUG_("LC_DYSYMTAB\n");
            break;
        case LC_LOAD_DYLIB: /* 0xc */
            DEBUG_("LC_LOAD_DYLIB\n");
            break;
        case LC_LOAD_DYLINKER: /* 0xe */
            DEBUG_("LC_LOAD_DYLINKER\n");
            break;
        case LC_UUID: /* 0x1b */
            DEBUG_("LC_UUID\n");
            break;
        case LC_VERSION_MIN_MACOSX: /* 0x24 */
            DEBUG_("LC_VERSION_MIN_MACOSX\n");
            break;
        case LC_FUNCTION_STARTS: /* 0x26 */
            DEBUG_("LC_FUNCTION_STARTS\n");
            break;
        case LC_MAIN: /* 0x28|LC_REQ_DYLD */
            DEBUG_("LC_MAIN\n");
            break;
        case LC_DATA_IN_CODE: /* 0x29 */
            DEBUG_("LC_DATA_IN_CODE\n");
            break;
        case LC_SOURCE_VERSION: /* 0x2A */
            DEBUG_("LC_SOURCE_VERSION\n");
            break;
        case LC_DYLIB_CODE_SIGN_DRS: /* 0x2B */
            DEBUG_("LC_DYLIB_CODE_SIGN_DRS\n");
            break;
        default:
            DEBUG_("LC_? (0x%x)\n", cmd->cmd);
        }
        cmd = (struct load_command *)((size_t)cmd + cmd->cmdsize);
    }
    nbind = get_bind_addr(NULL, base, lazy_bind_off, lazy_bind_size, segments);
    *plthook_out = (plthook_t*)malloc(offsetof(plthook_t, entries) + sizeof(bind_address_t) * nbind);
    (*plthook_out)->num_entries = nbind;
    get_bind_addr(*plthook_out, base, lazy_bind_off, lazy_bind_size, segments);

    return 0;
}

static unsigned int get_bind_addr(plthook_t *plthook, const uint8_t *base, uint32_t lazy_bind_off, uint32_t lazy_bind_size, struct segment_command **segments)
{
    const uint8_t *ptr = base + lazy_bind_off;
    const uint8_t *end = ptr + lazy_bind_size;
    const char *sym_name;
    int seg_index = 0;
    uint64_t seg_offset = 0;
    int count, skip;
    unsigned int idx = 0;

    while (ptr < end) {
        uint8_t op = *ptr & BIND_OPCODE_MASK;
        uint8_t imm = *ptr & BIND_IMMEDIATE_MASK;
        uint64_t ulebval;
        int64_t slebval;
        int i;

        ptr++;
        switch (op) {
        case BIND_OPCODE_DONE:
            DEBUG_("BIND_OPCODE_DONE\n");
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            DEBUG_("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: ordinal = %u\n", imm);
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            ulebval = uleb128(&ptr);
            DEBUG_("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: ordinal = %llu\n", ulebval);
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (imm == 0) {
                DEBUG_("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = 0\n");
            } else {
                DEBUG_("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = %u\n", BIND_OPCODE_MASK | imm);
            }
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char*)ptr;
            ptr += strlen(sym_name) + 1;
            DEBUG_("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: sym_name = %s\n", sym_name);
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            DEBUG_("BIND_OPCODE_SET_TYPE_IMM: type = %u\n", imm);
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            slebval = sleb128(&ptr);
            DEBUG_("BIND_OPCODE_SET_ADDEND_SLEB: ordinal = %lld\n", slebval);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = uleb128(&ptr);
            DEBUG_("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: seg_index = %u, seg_offset = %llu\n", seg_index, seg_offset);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_("BIND_OPCODE_ADD_ADDR_ULEB: seg_offset = %llu\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND:
            set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
            DEBUG_("BIND_OPCODE_DO_BIND\n");
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: seg_offset = %llu\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
            seg_offset += imm * sizeof(void *);
            DEBUG_("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = uleb128(&ptr);
            skip = uleb128(&ptr);
            for (i = 0; i < count; i++) {
                set_bind_addr(&idx, plthook, base, sym_name, seg_index, seg_offset, segments);
                seg_offset += skip;
            }
            DEBUG_("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");
            break;
        }
    }
    return idx;
}

static void set_bind_addr(unsigned int *idx, plthook_t *plthook, const uint8_t *base, const char *sym_name, int seg_index, int seg_offset, struct segment_command **segments)
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
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int rv;

    if (plthook == NULL) {
        set_errmsg("invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }
    while ((rv = plthook_enum(plthook, &pos, &name, &addr)) == 0) {
        if (name[0] == '_') {
            name++;
        }
        if (strcmp(name, funcname) == 0) {
            if (oldfunc) {
                *oldfunc = *addr;
            }
            *addr = funcaddr;
            return 0;
        }
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
