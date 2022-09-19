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
#include <unistd.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <mach-o/fixup-chains.h>
#include "plthook.h"

// #define PLTHOOK_DEBUG_CMD 1
// #define PLTHOOK_DEBUG_BIND 1
// #define PLTHOOK_DEBUG_FIXUPS 1
// #define PLTHOOK_DEBUG_ADDR 1

#ifdef PLTHOOK_DEBUG_CMD
#define DEBUG_CMD(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_CMD(...)
#endif

#ifdef PLTHOOK_DEBUG_FIXUPS
#define DEBUG_FIXUPS(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_FIXUPS(...)
#endif

#ifdef PLTHOOK_DEBUG_BIND
#define DEBUG_BIND(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_BIND(...)
#endif

#ifdef PLTHOOK_DEBUG_ADDR
#include <mach/mach.h>

#define INHERIT_MAX_SIZE 11
static char *inherit_to_str(vm_inherit_t inherit, char *buf)
{
    switch (inherit) {
    case VM_INHERIT_SHARE: return "share";
    case VM_INHERIT_COPY: return "copy";
    case VM_INHERIT_NONE: return "none";
    case VM_INHERIT_DONATE_COPY: return "donate_copy";
    default:
        sprintf(buf, "%d", inherit);
        return buf;
    }
}

#define BEHAVIOR_MAX_SIZE 16
static char *behavior_to_str(vm_behavior_t behavior, char *buf)
{
    switch (behavior) {
    case VM_BEHAVIOR_DEFAULT: return "default";
    case VM_BEHAVIOR_RANDOM: return "random";
    case VM_BEHAVIOR_SEQUENTIAL: return "sequential";
    case VM_BEHAVIOR_RSEQNTL: return "rseqntl";
    case VM_BEHAVIOR_WILLNEED: return "willneed";
    case VM_BEHAVIOR_DONTNEED: return "dontneed";
    case VM_BEHAVIOR_FREE: return "free";
    case VM_BEHAVIOR_ZERO_WIRED_PAGES: return "zero";
    case VM_BEHAVIOR_REUSABLE: return "reusable";
    case VM_BEHAVIOR_REUSE: return "reuse";
    case VM_BEHAVIOR_CAN_REUSE: return "can";
    case VM_BEHAVIOR_PAGEOUT: return "pageout";
    default:
        sprintf(buf, "%d", behavior);
        return buf;
    }
}

static void dump_maps(const char *image_name)
{
    mach_port_t task = mach_task_self();
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;
    vm_address_t addr = 0;
    vm_size_t size;
    char inherit_buf[INHERIT_MAX_SIZE + 1];
    char behavior_buf[BEHAVIOR_MAX_SIZE + 1];

    fprintf(stderr, "MEMORY MAP(%s)\n", image_name);
    fprintf(stderr, " start address    end address      protection    max_protection inherit     shared reserved offset   behavior         user_wired_count\n");
    while (vm_region_64(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) == KERN_SUCCESS) {
        fprintf(stderr, " %016lx-%016lx %c%c%c(%08x) %c%c%c(%08x)  %-*s %c      %c        %08llx %-*s %u\n",
                addr, addr + size,
                (info.protection & VM_PROT_READ) ? 'r' : '-',
                (info.protection & VM_PROT_WRITE) ? 'w' : '-',
                (info.protection & VM_PROT_EXECUTE) ? 'x' : '-',
                info.protection,
                (info.max_protection & VM_PROT_READ) ? 'r' : '-',
                (info.max_protection & VM_PROT_WRITE) ? 'w' : '-',
                (info.max_protection & VM_PROT_EXECUTE) ? 'x' : '-',
                info.max_protection,
                INHERIT_MAX_SIZE, inherit_to_str(info.inheritance, inherit_buf),
                info.shared ? 'Y' : 'N',
                info.reserved ? 'Y' : 'N',
                info.offset,
                BEHAVIOR_MAX_SIZE, behavior_to_str(info.behavior, behavior_buf),
                info.user_wired_count);
        addr += size;
    }
}
#endif

typedef struct {
    const char *name;
    void **addr;
} bind_address_t;

struct plthook {
    unsigned int num_entries;
    int readonly_segment;
    bind_address_t entries[1]; /* This must be the last. */
};

#define MAX_SEGMENTS 8

typedef struct {
    plthook_t *plthook;
    intptr_t slide;
    int num_segments;
    int linkedit_segment_idx;
    struct segment_command_64 *segments[MAX_SEGMENTS];
    struct linkedit_data_command *chained_fixups;
    size_t got_addr;
} data_t;

static int plthook_open_real(plthook_t **plthook_out, uint32_t image_idx, const struct mach_header *mh, const char *image_name);
static unsigned int set_bind_addrs(data_t *d, uint32_t lazy_bind_off, uint32_t lazy_bind_size);
static void set_bind_addr(data_t *d, unsigned int *idx, const char *sym_name, int seg_index, int seg_offset);
static int read_chained_fixups(data_t *d, const struct mach_header *mh, const char *image_name);

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
    if (mh == NULL) {
        mh = _dyld_get_image_header(image_idx);
    }
    if (image_name == NULL) {
        image_name = _dyld_get_image_name(image_idx);
    }
#if defined(PLTHOOK_DEBUG_CMD) || defined(PLTHOOK_DEBUG_ADDR)
    fprintf(stderr, "mh=%"PRIxPTR" slide=%"PRIxPTR"\n", (uintptr_t)mh, data.slide);
#endif
#ifdef PLTHOOK_DEBUG_ADDR
    dump_maps(image_name);
#endif

    cmd = (struct load_command *)((size_t)mh + sizeof(struct mach_header_64));
    DEBUG_CMD("CMD START\n");
    for (i = 0; i < mh->ncmds; i++) {
        struct dyld_info_command *dyld_info;
#ifdef PLTHOOK_DEBUG_CMD
        struct segment_command *segment;
#endif
        struct segment_command_64 *segment64;

        switch (cmd->cmd) {
        case LC_SEGMENT: /* 0x1 */
#ifdef PLTHOOK_DEBUG_CMD
            segment = (struct segment_command *)cmd;
#endif
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
                data.linkedit_segment_idx = data.num_segments;
            }
            if (strcmp(segment64->segname, "__DATA_CONST") == 0) {
                struct section_64 *sec = (struct section_64 *)(segment64 + 1);
                uint32_t i;
                for (i = 0; i < segment64->nsects; i++) {
                    DEBUG_CMD("  section_64 (%u)\n"
                              "      sectname  %s\n"
                              "      segname   %s\n"
                              "      addr      0x%llx\n"
                              "      size      0x%llx\n"
                              "      offset    0x%x\n"
                              "      align     0x%x\n"
                              "      reloff    0x%x\n"
                              "      nreloc    %d\n"
                              "      flags     0x%x\n"
                              "      reserved1 %d\n"
                              "      reserved2 %d\n"
                              "      reserved3 %d\n",
                              i,
                              sec->sectname,
                              sec->segname,
                              sec->addr,
                              sec->size,
                              sec->offset,
                              sec->align,
                              sec->reloff,
                              sec->nreloc,
                              sec->flags,
                              sec->reserved1,
                              sec->reserved2,
                              sec->reserved3);
                    if (strcmp(sec->segname, "__DATA_CONST") == 0 && strcmp(sec->sectname, "__got") == 0) {
                        data.got_addr = sec->addr + data.slide;
                    }
                    sec++;
                }
            }
            if (data.num_segments == MAX_SEGMENTS) {
                set_errmsg("Too many segments: %s", image_name);
                return PLTHOOK_INTERNAL_ERROR;
            }
            data.segments[data.num_segments++] = segment64;
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
        case LC_CODE_SIGNATURE: /* 0x1d */
            DEBUG_CMD("LC_CODE_SIGNATURE\n");
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
        case LC_BUILD_VERSION: /* 0x32 */
            DEBUG_CMD("LC_BUILD_VERSION\n");
            break;
        case LC_DYLD_EXPORTS_TRIE: /* (0x33|LC_REQ_DYLD) */
            DEBUG_CMD("LC_DYLD_EXPORTS_TRIE\n");
            break;
        case LC_DYLD_CHAINED_FIXUPS: /* (0x34|LC_REQ_DYLD) */
            data.chained_fixups = (struct linkedit_data_command *)cmd;
            DEBUG_CMD("LC_DYLD_CHAINED_FIXUPS\n"
                      "  cmdsize   %u\n"
                      "  dataoff   %u (0x%x)\n"
                      "  datasize  %u\n",
                      data.chained_fixups->cmdsize,
                      data.chained_fixups->dataoff,
                      data.chained_fixups->dataoff,
                      data.chained_fixups->datasize);
            break;
        default:
            DEBUG_CMD("LC_? (0x%x)\n", cmd->cmd);
        }
        cmd = (struct load_command *)((size_t)cmd + cmd->cmdsize);
    }
    DEBUG_CMD("CMD END\n");
    if (data.linkedit_segment_idx == -1) {
        set_errmsg("Cannot find the linkedit segment: %s", image_name);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (data.chained_fixups != NULL) {
        int rv = read_chained_fixups(&data, mh, image_name);
        if (rv != 0) {
            return rv;
        }
    } else {
        nbind = set_bind_addrs(&data, lazy_bind_off, lazy_bind_size);
        size = offsetof(plthook_t, entries) + sizeof(bind_address_t) * nbind;
        data.plthook = (plthook_t*)calloc(1, size);
        if (data.plthook == NULL) {
            set_errmsg("failed to allocate memory: %" PRIuPTR " bytes", size);
            return PLTHOOK_OUT_OF_MEMORY;
        }
        data.plthook->num_entries = nbind;
        set_bind_addrs(&data, lazy_bind_off, lazy_bind_size);
    }

    *plthook_out = data.plthook;
    return 0;
}

static unsigned int set_bind_addrs(data_t *data, uint32_t lazy_bind_off, uint32_t lazy_bind_size)
{
    struct segment_command_64 *linkedit = data->segments[data->linkedit_segment_idx];
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
#ifdef PLTHOOK_DEBUG_BIND
            DEBUG_BIND("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: ordinal = %llu\n", uleb128(&ptr));
#else
            uleb128(&ptr);
#endif
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
#ifdef PLTHOOK_DEBUG_BIND
            DEBUG_BIND("BIND_OPCODE_SET_ADDEND_SLEB: ordinal = %lld\n", sleb128(&ptr));
#else
            sleb128(&ptr);
#endif
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

static int read_chained_fixups(data_t *d, const struct mach_header *mh, const char *image_name)
{
    const uint8_t *ptr = (const uint8_t *)mh + d->chained_fixups->dataoff;
    const uint8_t *end = ptr + d->chained_fixups->datasize;
    const struct dyld_chained_fixups_header *header = (const struct dyld_chained_fixups_header *)ptr;
    const struct dyld_chained_import *import = (const struct dyld_chained_import *)(ptr + header->imports_offset);
    const struct dyld_chained_import_addend *import_addend = (const struct dyld_chained_import_addend *)(ptr + header->imports_offset);
    const struct dyld_chained_import_addend64 *import_addend64 = (const struct dyld_chained_import_addend64 *)(ptr + header->imports_offset);
    const char *symbol_pool = (const char*)ptr + header->symbols_offset;
    int rv = PLTHOOK_INTERNAL_ERROR;
    size_t size;
    uint32_t i;
#ifdef PLTHOOK_DEBUG_FIXUPS
    const struct dyld_chained_starts_in_image *starts = (const struct dyld_chained_starts_in_image *)(ptr + header->starts_offset);
    FILE *fp = NULL;
#endif
    if (d->got_addr == 0) {
        set_errmsg("__got section is not found in %s", image_name);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto cleanup;
    }

    DEBUG_FIXUPS("dyld_chained_fixups_header\n"
                 "  fixups_version  %u\n"
                 "  starts_offset   %u\n"
                 "  imports_offset  %u\n"
                 "  symbols_offset  %u\n"
                 "  imports_count   %u\n"
                 "  imports_format  %u\n"
                 "  symbols_format  %u\n",
                 header->fixups_version,
                 header->starts_offset,
                 header->imports_offset,
                 header->symbols_offset,
                 header->imports_count,
                 header->imports_format,
                 header->symbols_format);
    if (header->fixups_version != 0) {
        set_errmsg("unknown chained fixups version %u", header->fixups_version);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto cleanup;
    }

    size = offsetof(plthook_t, entries) + sizeof(bind_address_t) * header->imports_count;
    d->plthook = (plthook_t*)calloc(1, size);
    if (d->plthook == NULL) {
        set_errmsg("failed to allocate memory: %" PRIuPTR " bytes", size);
        rv = PLTHOOK_OUT_OF_MEMORY;
        goto cleanup;
    }
    d->plthook->num_entries = header->imports_count;
    d->plthook->readonly_segment = 1;

    switch (header->imports_format) {
    case DYLD_CHAINED_IMPORT:
        DEBUG_FIXUPS("dyld_chained_import\n");
        break;
    case DYLD_CHAINED_IMPORT_ADDEND:
        DEBUG_FIXUPS("dyld_chained_import_addend\n");
        break;
    case DYLD_CHAINED_IMPORT_ADDEND64:
        DEBUG_FIXUPS("dyld_chained_import_addend64\n");
        break;
    default:
        set_errmsg("unknown imports format %u", header->imports_format);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto cleanup;
    }

    for (i = 0; i < header->imports_count; i++) {
        struct dyld_chained_import_addend64 imp;
        switch (header->imports_format) {
        case DYLD_CHAINED_IMPORT:
            imp.lib_ordinal = import[i].lib_ordinal;
            imp.weak_import = import[i].weak_import;
            imp.name_offset = import[i].name_offset;
            imp.addend = 0;
            break;
        case DYLD_CHAINED_IMPORT_ADDEND:
            imp.lib_ordinal = import_addend[i].lib_ordinal;
            imp.weak_import = import_addend[i].weak_import;
            imp.name_offset = import_addend[i].name_offset;
            imp.addend = import_addend[i].addend;
            break;
        case DYLD_CHAINED_IMPORT_ADDEND64:
            imp = import_addend64[i];
            break;
        }
        const char *name = symbol_pool + imp.name_offset;
        if (name > (const char*)end) {
            DEBUG_FIXUPS("  lib_ordinal %u, weak_import %u, name_offset %u, addend %llu\n",
                         imp.lib_ordinal, imp.weak_import, imp.name_offset, imp.addend);
            set_errmsg("invalid symbol name address");
            rv = PLTHOOK_INVALID_FILE_FORMAT;
            goto cleanup;
        }
        DEBUG_FIXUPS("  lib_ordinal %u, weak_import %u, name_offset %u (%s), addend %llu\n",
                     imp.lib_ordinal, imp.weak_import, imp.name_offset, name, imp.addend);
        d->plthook->entries[i].name = name;
        d->plthook->entries[i].addr = (void**)(d->got_addr + i * sizeof(void*));
    }

#ifdef PLTHOOK_DEBUG_FIXUPS
    fp = fopen(image_name, "r");
    if (fp == NULL) {
        set_errmsg("failed to open file %s (error: %s)", image_name, strerror(errno));
        rv = PLTHOOK_FILE_NOT_FOUND;
        goto cleanup;
    }

    DEBUG_FIXUPS("dyld_chained_starts_in_image\n"
                 "  seg_count       %u\n",
                 starts->seg_count);
    for (i = 0; i < starts->seg_count; i++) {
        DEBUG_FIXUPS("  seg_info_offset[%u] %u\n",
                     i, starts->seg_info_offset[i]);
        if (starts->seg_info_offset[i] == 0) {
            continue;
        }
        const struct dyld_chained_starts_in_segment* seg = (const struct dyld_chained_starts_in_segment*)((char*)starts + starts->seg_info_offset[i]);
        uint16_t j;
        DEBUG_FIXUPS("    dyld_chained_starts_in_segment\n"
                     "      size              %u\n"
                     "      page_size         0x%x\n"
                     "      pointer_format    %u\n"
                     "      segment_offset    %llu (0x%llx)\n"
                     "      max_valid_pointer %u\n"
                     "      page_count        %u\n",
                     seg->size, seg->page_size, seg->pointer_format, seg->segment_offset, seg->segment_offset, seg->max_valid_pointer, seg->page_count);
        for (j = 0; j < seg->page_count; j++) {
            uint16_t index = j;
            uint16_t break_loop = 1;
            off_t offset;

            if (seg->page_start[j] == DYLD_CHAINED_PTR_START_NONE) {
                DEBUG_FIXUPS("      page_start[%u]     DYLD_CHAINED_PTR_START_NONE\n", j);
                continue;
            }
            if (seg->page_start[j] & DYLD_CHAINED_PTR_START_MULTI) {
                index = seg->page_start[j] & ~DYLD_CHAINED_PTR_START_MULTI;
                DEBUG_FIXUPS("      page_start[%u]     (DYLD_CHAINED_PTR_START_MULTI | %u)\n", j, index);
                break_loop = 0;
            }
            while (1) {
                if (index != j) {
                    DEBUG_FIXUPS("      page_start[%u]     %u\n", index, seg->page_start[index]);
                }
                offset = seg->segment_offset + j * seg->page_size + (seg->page_start[index] & ~DYLD_CHAINED_PTR_START_MULTI);
                switch (seg->pointer_format) {
                case DYLD_CHAINED_PTR_64_OFFSET: {
                    union {
                        struct dyld_chained_ptr_64_rebase rebase;
                        struct dyld_chained_ptr_64_bind bind;
                    } buf;

                    do {
                        if (fseeko(fp, offset, SEEK_SET) != 0) {
                            set_errmsg("failed to seek to %lld in %s", offset, image_name);
                            rv = PLTHOOK_INVALID_FILE_FORMAT;
                            goto cleanup;
                        }
                        if (fread(&buf, sizeof(buf), 1, fp) != 1) {
                            set_errmsg("failed to read fixup chain from %s", image_name);
                            rv = PLTHOOK_INVALID_FILE_FORMAT;
                            goto cleanup;
                        }
                        if (buf.rebase.bind) {
                            DEBUG_FIXUPS("        dyld_chained_ptr_64_bind\n"
                                         "          ordinal  %d\n"
                                         "          addend   %d\n"
                                         "          reserved %d\n"
                                         "          next     %d\n"
                                         "          bind     %d\n",
                                         buf.bind.ordinal,
                                         buf.bind.addend,
                                         buf.bind.reserved,
                                         buf.bind.next,
                                         buf.bind.bind);
                        } else {
                            DEBUG_FIXUPS("        dyld_chained_ptr_64_rebase\n"
                                         "          target   %llu\n"
                                         "          high8    %d\n"
                                         "          reserved %d\n"
                                         "          next     %d\n"
                                         "          bind     %d\n",
                                         buf.rebase.target,
                                         buf.rebase.high8,
                                         buf.rebase.reserved,
                                         buf.rebase.next,
                                         buf.rebase.bind);
                        }
                        offset += buf.bind.next * 4;
                    } while (buf.bind.next != 0);
                    break;
                }
                case DYLD_CHAINED_PTR_ARM64E:
                case DYLD_CHAINED_PTR_ARM64E_KERNEL:
                case DYLD_CHAINED_PTR_ARM64E_USERLAND:
                case DYLD_CHAINED_PTR_ARM64E_USERLAND24: {
                    // The following code isn't tested.
                    union {
                        struct dyld_chained_ptr_arm64e_rebase rebase;
                        struct dyld_chained_ptr_arm64e_bind bind;
                        struct dyld_chained_ptr_arm64e_bind24 bind24;
                        struct dyld_chained_ptr_arm64e_auth_rebase auth_rebase;
                        struct dyld_chained_ptr_arm64e_auth_bind auth_bind;
                        struct dyld_chained_ptr_arm64e_auth_bind24 auth_bind24;
                    } buf;

                    do {
                        if (fseeko(fp, offset, SEEK_SET) != 0) {
                            set_errmsg("failed to seek to %lld in %s", offset, image_name);
                            rv = PLTHOOK_INVALID_FILE_FORMAT;
                            goto cleanup;
                        }
                        if (fread(&buf, sizeof(buf), 1, fp) != 1) {
                            set_errmsg("failed to read fixup chain from %s", image_name);
                            rv = PLTHOOK_INVALID_FILE_FORMAT;
                            goto cleanup;
                        }
                        if (!buf.rebase.auth) {
                            if (!buf.rebase.bind) {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_rebase\n"
                                             "          target    %llu\n"
                                             "          high8     %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 0
                                             "          auth      %d\n", // == 0
                                             buf.rebase.target,
                                             buf.rebase.high8,
                                             buf.rebase.next,
                                             buf.rebase.bind,
                                             buf.rebase.auth);
                            } else if (seg->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_bind\n"
                                             "          ordinal   %d\n"
                                             "          zero      %d\n"
                                             "          addend    %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 1
                                             "          auth      %d\n", // == 0
                                             buf.bind.ordinal,
                                             buf.bind.zero,
                                             buf.bind.addend,
                                             buf.bind.next,
                                             buf.bind.bind,
                                             buf.bind.auth);
                            } else {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_bind24\n"
                                             "          ordinal   %d\n"
                                             "          zero      %d\n"
                                             "          addend    %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 1
                                             "          auth      %d\n", // == 0
                                             buf.bind24.ordinal,
                                             buf.bind24.zero,
                                             buf.bind24.addend,
                                             buf.bind24.next,
                                             buf.bind24.bind,
                                             buf.bind24.auth);
                            }
                        } else {
                            if (!buf.rebase.bind) {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_auth_rebase\n"
                                             "          target    %u\n"
                                             "          diversity %d\n"
                                             "          addrDiv   %d\n"
                                             "          key       %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 0
                                             "          auth      %d\n", // == 1
                                             buf.auth_rebase.target,
                                             buf.auth_rebase.diversity,
                                             buf.auth_rebase.addrDiv,
                                             buf.auth_rebase.key,
                                             buf.auth_rebase.next,
                                             buf.auth_rebase.bind,
                                             buf.auth_rebase.auth);
                            } else if (seg->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_auth_bind\n"
                                             "          ordinal   %d\n"
                                             "          zero      %d\n"
                                             "          diversity %d\n"
                                             "          addrDiv   %d\n"
                                             "          key       %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 1
                                             "          auth      %d\n", // == 1
                                             buf.auth_bind.ordinal,
                                             buf.auth_bind.zero,
                                             buf.auth_bind.diversity,
                                             buf.auth_bind.addrDiv,
                                             buf.auth_bind.key,
                                             buf.auth_bind.next,
                                             buf.auth_bind.bind,
                                             buf.auth_bind.auth);
                            } else {
                                DEBUG_FIXUPS("        dyld_chained_ptr_arm64e_auth_bind24\n"
                                             "          ordinal   %d\n"
                                             "          zero      %d\n"
                                             "          diversity %d\n"
                                             "          addrDiv   %d\n"
                                             "          key       %d\n"
                                             "          next      %d\n"
                                             "          bind      %d\n"  // == 1
                                             "          auth      %d\n", // == 1
                                             buf.auth_bind24.ordinal,
                                             buf.auth_bind24.zero,
                                             buf.auth_bind24.diversity,
                                             buf.auth_bind24.addrDiv,
                                             buf.auth_bind24.key,
                                             buf.auth_bind24.next,
                                             buf.auth_bind24.bind,
                                             buf.auth_bind24.auth);
                            }
                        }
                        if (seg->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
                            offset += buf.rebase.next * 4;
                        } else {
                            offset += buf.rebase.next * 8;
                        }
                    } while (buf.rebase.next != 0);
                    break;
                }
                default:
                    DEBUG_FIXUPS("unsupported pointer_format: %u\n", seg->pointer_format);
                    break_loop = 1;
                    break;
                }
                if (break_loop) {
                    break;
                }
                break_loop = seg->page_start[++index] & DYLD_CHAINED_PTR_START_MULTI;
            } // while (1) */
        }
    }
#endif
    rv = 0;
cleanup:
#ifdef PLTHOOK_DEBUG_FIXUPS
    if (fp != NULL) {
        fclose(fp);
    }
#endif
    if (rv != 0 && d->plthook) {
        free(d->plthook);
        d->plthook = NULL;
    }
    return rv;
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
        if (plthook->readonly_segment) {
            size_t page_size = sysconf(_SC_PAGESIZE);
            void *base = (void*)((size_t)addr & ~(page_size - 1));
            if (mprotect(base, page_size, PROT_READ | PROT_WRITE) != 0) {
                set_errmsg("Cannot change memory protection at address %p", base);
                return PLTHOOK_INTERNAL_ERROR;
            }
            *addr = funcaddr;
            mprotect(base, page_size, PROT_READ);
        } else {
            *addr = funcaddr;
        }
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
