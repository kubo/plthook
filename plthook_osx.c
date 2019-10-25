/* -*- indent-tabs-mode: nil -*-
 *
 * plthook_osx.c -- implementation of plthook for OS X
 *
 * URL: https://github.com/kubo/plthook
 *
 * ------------------------------------------------------
 *
 * Copyright 2014-2019 Kubo Takehiro <kubo@jiubao.org>
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
#include <inttypes.h>
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

#define MAX_SEGMENTS 8

typedef struct {
    plthook_t *plthook;
    intptr_t slide;
    int num_segments;
    int linkedit_segment_idx;
    struct segment_command_ *segments[MAX_SEGMENTS];
} data_t;

static int plthook_open_real(plthook_t **plthook_out, uint32_t image_idx, const struct mach_header *mh, const char *image_name);
static unsigned int set_bind_addrs(data_t *d, uint32_t lazy_bind_off, uint32_t lazy_bind_size);
static void set_bind_addr(data_t *d, unsigned int *idx, const char *sym_name, int seg_index, int seg_offset);

static void set_errmsg(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));

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
    size_t namelen;
    uint32_t cnt;
    uint32_t idx;

    if (filename == NULL) {
        return plthook_open_real(plthook_out, 0, NULL, NULL);
    }
    cnt = _dyld_image_count();
    namelen = strlen(filename);
    namelen = strlen(filename);
    cnt = _dyld_image_count();

    for (idx = 0; idx < cnt; idx++) {
        const char *image_name = _dyld_get_image_name(idx);
        size_t offset = 0;

        if (image_name == NULL) {
            *plthook_out = NULL;
            set_errmsg("Cannot find file at image index %u", idx);
            return PLTHOOK_INTERNAL_ERROR;
        }
        if (*filename != '/') {
            size_t image_name_len = strlen(image_name);
            if (image_name_len > namelen) {
              offset = image_name_len - namelen;
            }
        }
        if (strcmp(image_name + offset, filename) == 0) {
            return plthook_open_real(plthook_out, idx, NULL, image_name);
        }
    }
    *plthook_out = NULL;
    set_errmsg("Cannot find file: %s", filename);
    return PLTHOOK_FILE_NOT_FOUND;
}

int plthook_open_by_handle(plthook_t **plthook_out, void *hndl)
{
    int flags[] = {
        RTLD_LAZY | RTLD_NOLOAD,
        RTLD_LAZY | RTLD_NOLOAD | RTLD_FIRST,
    };
    int flag_idx;
    uint32_t cnt = _dyld_image_count();
#define NUM_FLAGS (sizeof(flags) / sizeof(flags[0]))

    if (hndl == NULL) {
        set_errmsg("NULL handle");
        return PLTHOOK_FILE_NOT_FOUND;
    }
    for (flag_idx = 0; flag_idx < NUM_FLAGS; flag_idx++) {
        uint32_t idx;

        for (idx = 0; idx < cnt; idx++) {
            const char *image_name = idx ? _dyld_get_image_name(idx) : NULL;
            void *handle = dlopen(image_name, flags[flag_idx]);
            if (handle != NULL) {
                dlclose(handle);
                if (handle == hndl) {
                    return plthook_open_real(plthook_out, idx, NULL, image_name);
                }
            }
        }
    }
    set_errmsg("Cannot find the image correspond to handle %p", hndl);
    return PLTHOOK_FILE_NOT_FOUND;
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
    Dl_info dlinfo;
    uint32_t idx = 0;
    uint32_t cnt = _dyld_image_count();

    if (!dladdr(address, &dlinfo)) {
        *plthook_out = NULL;
        set_errmsg("Cannot find address: %p", address);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    for (idx = 0; idx < cnt; idx++) {
        if (dlinfo.dli_fbase == _dyld_get_image_header(idx)) {
            return plthook_open_real(plthook_out, idx, dlinfo.dli_fbase, dlinfo.dli_fname);
        }
    }
    set_errmsg("Cannot find the image index for base address: %p", dlinfo.dli_fbase);
    return PLTHOOK_FILE_NOT_FOUND;
}

static int plthook_open_real(plthook_t **plthook_out, uint32_t image_idx, const struct mach_header *mh, const char *image_name)
{
    struct load_command *cmd;
    uint32_t lazy_bind_off = 0;
    uint32_t lazy_bind_size = 0;
    unsigned int nbind;
    data_t data = {NULL,};
    size_t size;
    int i;

    data.linkedit_segment_idx = -1;
    data.slide = _dyld_get_image_vmaddr_slide(image_idx);
    DEBUG_CMD("slide=%"PRIxPTR"\n", data.slide);
    if (mh == NULL) {
        mh = _dyld_get_image_header(image_idx);
    }
    if (image_name == NULL) {
        image_name = _dyld_get_image_name(image_idx);
    }

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
#ifndef __LP64__
            if (strcmp(segment->segname, "__LINKEDIT") == 0) {
                data.linkedit_segment_idx = data.num_segments;
            }
            if (data.num_segments == MAX_SEGMENTS) {
                set_errmsg("Too many segments:  %s", image_name);
                return PLTHOOK_INTERNAL_ERROR;
            }
            data.segments[data.num_segments++] = segment;
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
#ifdef __LP64__
            if (strcmp(segment64->segname, "__LINKEDIT") == 0) {
                data.linkedit_segment_idx = data.num_segments;
            }
            if (data.num_segments == MAX_SEGMENTS) {
                set_errmsg("Too many segments: %s", image_name);
                return PLTHOOK_INTERNAL_ERROR;
            }
            data.segments[data.num_segments++] = segment64;
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
    if (data.linkedit_segment_idx == -1) {
        set_errmsg("Cannot find the linkedit segment: %s", image_name);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    nbind = set_bind_addrs(&data, lazy_bind_off, lazy_bind_size);
    size = offsetof(plthook_t, entries) + sizeof(bind_address_t) * nbind;
    data.plthook = (plthook_t*)malloc(size);
    if (data.plthook == NULL) {
        set_errmsg("failed to allocate memory: %" PRIuPTR " bytes", size);
        return PLTHOOK_OUT_OF_MEMORY;
    }
    data.plthook->num_entries = nbind;
    set_bind_addrs(&data, lazy_bind_off, lazy_bind_size);

    *plthook_out = data.plthook;
    return 0;
}

static unsigned int set_bind_addrs(data_t *data, uint32_t lazy_bind_off, uint32_t lazy_bind_size)
{
    struct segment_command_ *linkedit = data->segments[data->linkedit_segment_idx];
    const uint8_t *ptr = (uint8_t*)(linkedit->vmaddr - linkedit->fileoff + data->slide + lazy_bind_off);
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
            set_bind_addr(data, &idx, sym_name, seg_index, seg_offset);
            DEBUG_BIND("BIND_OPCODE_DO_BIND\n");
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: seg_offset = 0x%llx\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            set_bind_addr(data, &idx, sym_name, seg_index, seg_offset);
            seg_offset += imm * sizeof(void *);
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = uleb128(&ptr);
            skip = uleb128(&ptr);
            for (i = 0; i < count; i++) {
                set_bind_addr(data, &idx, sym_name, seg_index, seg_offset);
                seg_offset += skip;
            }
            DEBUG_BIND("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");
            break;
        }
    }
    return idx;
}

static void set_bind_addr(data_t *data, unsigned int *idx, const char *sym_name, int seg_index, int seg_offset)
{
    if (data->plthook != NULL) {
        size_t vmaddr = data->segments[seg_index]->vmaddr;
        data->plthook->entries[*idx].name = sym_name;
        data->plthook->entries[*idx].addr = (void**)(vmaddr + data->slide + seg_offset);
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
