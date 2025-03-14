/* -*- indent-tabs-mode: nil -*-
 *
 * plthook_osx.c -- implementation of plthook for OS X
 *
 * URL: https://github.com/kubo/plthook
 *
 * ------------------------------------------------------
 *
 * Copyright 2014-2024 Kubo Takehiro <kubo@jiubao.org>
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
#include <mach/mach.h>
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
#define DEBUG_BIND_IF(cond, ...) if (cond) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_BIND(...)
#define DEBUG_BIND_IF(cond, ...)
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
    int addend;
    char weak;
    void **addr;
} bind_address_t;

typedef struct mem_prot {
    size_t start;
    size_t end;
    int prot;
} mem_prot_t;

#define NUM_MEM_PROT 100

struct plthook {
    unsigned int num_entries;
    mem_prot_t mem_prot[NUM_MEM_PROT];
    bind_address_t entries[1]; /* This must be the last. */
};

#define MAX_SEGMENTS 8
#define MAX_SECTIONS 30

typedef struct {
    plthook_t *plthook;
    intptr_t slide;
    int num_segments;
    int linkedit_segment_idx;
    const struct segment_command_64 *segments[MAX_SEGMENTS];
#ifdef PLTHOOK_DEBUG_FIXUPS
    int num_sections;
    const struct section_64 *sections[MAX_SECTIONS];
#endif
    const struct linkedit_data_command *chained_fixups;
} data_t;

static int plthook_open_real(plthook_t **plthook_out, uint32_t image_idx, const struct mach_header *mh, const char *image_name);
static unsigned int set_bind_addrs(data_t *data, unsigned int idx, uint32_t bind_off, uint32_t bind_size, char weak);
static void set_bind_addr(data_t *d, unsigned int *idx, const char *sym_name, int seg_index, int seg_offset, int addend, char weak);
static int read_chained_fixups(data_t *d, const struct mach_header *mh, const char *image_name);
#ifdef PLTHOOK_DEBUG_FIXUPS
static const char *segment_name_from_addr(data_t *d, size_t addr);
static const char *section_name_from_addr(data_t *d, size_t addr);
#endif

static int set_mem_prot(plthook_t *plthook);
static int get_mem_prot(plthook_t *plthook, void *addr);

static inline uint8_t *fileoff_to_vmaddr_in_segment(data_t *d, int segment_index, size_t offset)
{
    const struct segment_command_64 *seg = d->segments[segment_index];
    return (uint8_t *)(seg->vmaddr - seg->fileoff + d->slide + offset);
}
static uint8_t *fileoff_to_vmaddr(data_t *data, size_t offset);

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
    for (flag_idx = 0; flag_idx < (int)NUM_FLAGS; flag_idx++) {
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
    const struct dyld_info_command *dyld_info = NULL;
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
#ifdef PLTHOOK_DEBUG_FIXUPS
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
                sec++;
            }
#endif
            if (data.num_segments == MAX_SEGMENTS) {
                set_errmsg("Too many segments: %s", image_name);
                return PLTHOOK_INTERNAL_ERROR;
            }
            data.segments[data.num_segments++] = segment64;
#ifdef PLTHOOK_DEBUG_FIXUPS
            {
                struct section_64 *sec = (struct section_64 *)(segment64 + 1);
                struct section_64 *sec_end = sec + segment64->nsects;
                while (sec < sec_end) {
                    if (data.num_sections == MAX_SECTIONS) {
                        set_errmsg("Too many sections: %s", image_name);
                        return PLTHOOK_INTERNAL_ERROR;
                    }
                    data.sections[data.num_sections++] = sec;
                    sec++;
                }
            }
#endif
            break;
        case LC_DYLD_INFO_ONLY: /* (0x22|LC_REQ_DYLD) */
            dyld_info= (struct dyld_info_command *)cmd;
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
        case LC_RPATH: /* (0x1c|LC_REQ_DYLD) */
            DEBUG_CMD("LC_RPATH\n");
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
        nbind = 0;
        nbind = set_bind_addrs(&data, nbind, dyld_info->bind_off, dyld_info->bind_size, 0);
        nbind = set_bind_addrs(&data, nbind, dyld_info->weak_bind_off, dyld_info->weak_bind_size, 1);
        nbind = set_bind_addrs(&data, nbind, dyld_info->lazy_bind_off, dyld_info->lazy_bind_size, 0);
        size = offsetof(plthook_t, entries) + sizeof(bind_address_t) * nbind;
        data.plthook = (plthook_t*)calloc(1, size);
        if (data.plthook == NULL) {
            set_errmsg("failed to allocate memory: %" PRIuPTR " bytes", size);
            return PLTHOOK_OUT_OF_MEMORY;
        }
        data.plthook->num_entries = nbind;
        nbind = 0;
        nbind = set_bind_addrs(&data, nbind, dyld_info->bind_off, dyld_info->bind_size, 0);
        nbind = set_bind_addrs(&data, nbind, dyld_info->weak_bind_off, dyld_info->weak_bind_size, 1);
        nbind = set_bind_addrs(&data, nbind, dyld_info->lazy_bind_off, dyld_info->lazy_bind_size, 0);
    }
    set_mem_prot(data.plthook);

    *plthook_out = data.plthook;
    return 0;
}

static unsigned int set_bind_addrs(data_t *data, unsigned int idx, uint32_t bind_off, uint32_t bind_size, char weak)
{
    const uint8_t *ptr = fileoff_to_vmaddr_in_segment(data, data->linkedit_segment_idx, bind_off);
    const uint8_t *end = ptr + bind_size;
    const char *sym_name;
    int seg_index = 0;
    uint64_t seg_offset = 0;
    int addend = 0;
    int count, skip;
#ifdef PLTHOOK_DEBUG_BIND
    int cond = data->plthook != NULL;
#endif

    while (ptr < end) {
        uint8_t op = *ptr & BIND_OPCODE_MASK;
        uint8_t imm = *ptr & BIND_IMMEDIATE_MASK;
        int i;

        DEBUG_BIND_IF(cond, "0x%02x: ", *ptr);
        ptr++;
        switch (op) {
        case BIND_OPCODE_DONE:
            DEBUG_BIND_IF(cond, "BIND_OPCODE_DONE\n");
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: ordinal = %u\n", imm);
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
#ifdef PLTHOOK_DEBUG_BIND
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: ordinal = %llu\n", uleb128(&ptr));
#else
            uleb128(&ptr);
#endif
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (imm == 0) {
                DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = 0\n");
            } else {
                DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ordinal = %u\n", BIND_OPCODE_MASK | imm);
            }
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char*)ptr;
            ptr += strlen(sym_name) + 1;
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: sym_name = %s\n", sym_name);
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_TYPE_IMM: type = %u\n", imm);
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = sleb128(&ptr);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_ADDEND_SLEB: ordinal = %lld\n", addend);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm;
            seg_offset = uleb128(&ptr);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: seg_index = %u, seg_offset = 0x%llx\n", seg_index, seg_offset);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += uleb128(&ptr);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_ADD_ADDR_ULEB: seg_offset = 0x%llx\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND:
            set_bind_addr(data, &idx, sym_name, seg_index, seg_offset, addend, weak);
            seg_offset += sizeof(void*);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_DO_BIND\n");
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            set_bind_addr(data, &idx, sym_name, seg_index, seg_offset, addend, weak);
            seg_offset += uleb128(&ptr) + sizeof(void*);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: seg_offset = 0x%llx\n", seg_offset);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            set_bind_addr(data, &idx, sym_name, seg_index, seg_offset, addend, weak);
            seg_offset += imm * sizeof(void *) + sizeof(void*);
            DEBUG_BIND_IF(cond, "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = uleb128(&ptr);
            skip = uleb128(&ptr);
            for (i = 0; i < count; i++) {
                set_bind_addr(data, &idx, sym_name, seg_index, seg_offset, addend, weak);
                seg_offset += skip + sizeof(void*);
            }
            DEBUG_BIND_IF(cond, "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");
            break;
        default:
            DEBUG_BIND_IF(cond, "op: 0x%x, imm: 0x%x\n", op, imm);
        }
    }
    return idx;
}

static void set_bind_addr(data_t *data, unsigned int *idx, const char *sym_name, int seg_index, int seg_offset, int addend, char weak)
{
    if (data->plthook != NULL) {
        size_t vmaddr = data->segments[seg_index]->vmaddr;
        bind_address_t *bind_addr = &data->plthook->entries[*idx];
        bind_addr->name = sym_name;
        bind_addr->addend = addend;
        bind_addr->weak = weak;
        bind_addr->addr = (void**)(vmaddr + data->slide + seg_offset);
        DEBUG_BIND("bind_address[%u]: %s, %d, %d, %p, %p, %p\n", *idx, sym_name, seg_index, seg_offset, (void*)vmaddr, (void*)data->slide, bind_addr->addr);
    }
    (*idx)++;
}

typedef struct {
    const char *image_name;
    FILE *fp;
    const struct dyld_chained_starts_in_image *starts;
    uint32_t seg_index; // i
    uint16_t page_index; // j
    off_t offset;
} chained_fixups_iter_t;

typedef struct {
    uint16_t    ptr_format;
    union {
        uint64_t raw;
        struct dyld_chained_ptr_64_rebase rebase;
        struct dyld_chained_ptr_64_bind bind;
        struct dyld_chained_ptr_arm64e_rebase arm64e_rebase;
        struct dyld_chained_ptr_arm64e_bind arm64e_bind;
        struct dyld_chained_ptr_arm64e_bind24 arm64e_bind24;
        struct dyld_chained_ptr_arm64e_auth_rebase arm64e_auth_rebase;
        struct dyld_chained_ptr_arm64e_auth_bind arm64e_auth_bind;
        struct dyld_chained_ptr_arm64e_auth_bind24 arm64e_auth_bind24;
    } ptr;
    off_t offset;
} chianed_fixups_entry_t;

static int chained_fixups_iter_init(chained_fixups_iter_t *iter, const char *image_name, const struct dyld_chained_starts_in_image *starts_offset);
static void chained_fixups_iter_deinit(chained_fixups_iter_t *iter);
static int chained_fixups_iter_rewind(chained_fixups_iter_t *iter);
static int chained_fixups_iter_next(chained_fixups_iter_t *iter, chianed_fixups_entry_t *entry);

static int chained_fixups_iter_init(chained_fixups_iter_t *iter, const char *image_name, const struct dyld_chained_starts_in_image *starts)
{
    memset(iter, 0, sizeof(*iter));
    iter->fp = fopen(image_name, "r");
    if (iter->fp == NULL) {
        set_errmsg("failed to open file %s (error: %s)", image_name, strerror(errno));
        return PLTHOOK_FILE_NOT_FOUND;
    }
    iter->image_name = image_name;
    iter->starts = starts;
    return 0;
}

static void chained_fixups_iter_deinit(chained_fixups_iter_t *iter)
{
    if (iter->fp != NULL) {
        fclose(iter->fp);
        iter->fp = NULL;
    }
}

static int chained_fixups_iter_rewind(chained_fixups_iter_t *iter)
{
    iter->seg_index = 0;
    iter->page_index = 0;
    iter->offset = 0;
    return 0;
}

static int chained_fixups_iter_next(chained_fixups_iter_t *iter, chianed_fixups_entry_t *entry)
{
    const struct dyld_chained_starts_in_image *starts = iter->starts;
    uint32_t i = iter->seg_index;
    uint16_t j = iter->page_index;
    off_t offset = iter->offset;

next_segment:
    if (i == starts->seg_count) {
        return -1;
    }
    if (j == 0 && offset == 0) {
        DEBUG_FIXUPS("  seg_info_offset[%u] %u\n",
                     i, starts->seg_info_offset[i]);
    }
    if (starts->seg_info_offset[i] == 0) {
        i++;
        j = 0;
        offset = 0;
        goto next_segment;
    }
    const struct dyld_chained_starts_in_segment* seg = (const struct dyld_chained_starts_in_segment*)((char*)starts + starts->seg_info_offset[i]);
    if (j == 0 && offset == 0) {
        DEBUG_FIXUPS("    dyld_chained_starts_in_segment\n"
                     "      size              %u\n"
                     "      page_size         0x%x\n"
                     "      pointer_format    %u\n"
                     "      segment_offset    %llu (0x%llx)\n"
                     "      max_valid_pointer %u\n"
                     "      page_count        %u\n",
                     seg->size, seg->page_size, seg->pointer_format, seg->segment_offset, seg->segment_offset, seg->max_valid_pointer, seg->page_count);
    }
next_page:
    if (j == seg->page_count) {
        i++;
        j = 0;
        offset = 0;
        goto next_segment;
    }

    if (seg->page_start[j] == DYLD_CHAINED_PTR_START_NONE) {
        DEBUG_FIXUPS("      page_start[%u]     DYLD_CHAINED_PTR_START_NONE\n", j);
        j++;
        offset = 0;
        goto next_page;
    }
    if (offset == 0) {
        DEBUG_FIXUPS("      page_start[%u]     %u\n", j, seg->page_start[j]);
    }
    if (offset == 0) {
        offset = seg->segment_offset + j * seg->page_size + seg->page_start[j];
    }
    if (fseeko(iter->fp, offset, SEEK_SET) != 0) {
        set_errmsg("failed to seek to %lld in %s", offset, iter->image_name);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    entry->ptr_format = seg->pointer_format;
    if (fread(&entry->ptr, sizeof(entry->ptr), 1, iter->fp) != 1) {
        set_errmsg("failed to read fixup chain from %s", iter->image_name);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    entry->offset = offset;
    switch (seg->pointer_format) {
    case DYLD_CHAINED_PTR_64_OFFSET:
        if (entry->ptr.bind.next) {
            offset += entry->ptr.bind.next * 4;
        } else {
            j++;
            offset = 0;
        }
        break;
    default:
        set_errmsg("unsupported pointer format %u in %s", seg->pointer_format, iter->image_name);
        return PLTHOOK_INTERNAL_ERROR;
    }
    iter->seg_index = i;
    iter->page_index = j;
    iter->offset = offset;
    return 0;
}

static int read_chained_fixups(data_t *d, const struct mach_header *mh, const char *image_name)
{
    const uint8_t *ptr = fileoff_to_vmaddr_in_segment(d, d->linkedit_segment_idx, d->chained_fixups->dataoff);
    const struct dyld_chained_fixups_header *header = (const struct dyld_chained_fixups_header *)ptr;
    const char *symbol_pool = (const char*)ptr + header->symbols_offset;
    int rv;
    unsigned int num_binds;
    size_t size;
    const struct dyld_chained_starts_in_image *starts = (const struct dyld_chained_starts_in_image *)(ptr + header->starts_offset);
    const struct dyld_chained_import *import = (const struct dyld_chained_import *)(ptr + header->imports_offset);
    chained_fixups_iter_t iter = {NULL, };
    chianed_fixups_entry_t entry;

    rv = chained_fixups_iter_init(&iter, image_name, starts);
    if (rv != 0) {
        return rv;
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

    DEBUG_FIXUPS("dyld_chained_starts_in_image\n"
                 "  seg_count       %u\n",
                 starts->seg_count);
    num_binds = 0;
    while ((rv = chained_fixups_iter_next(&iter, &entry)) == 0) {
        if (entry.ptr_format == DYLD_CHAINED_PTR_64_OFFSET && entry.ptr.bind.bind) {
            num_binds++;
        }
#if 0
        if (entry.ptr.rebase.bind) {
            DEBUG_FIXUPS("  0x%08lX:  raw: 0x%016lX         bind: (next: %03u, ordinal: %06X, addend: %d)\n",
                         entry.offset, entry.ptr.raw, entry.ptr.bind.next, entry.ptr.bind.ordinal, entry.ptr.bind.addend);
        } else {
            DEBUG_FIXUPS("  0x%08lX:  raw: 0x%016lX       rebase: (next: %03u, target: 0x%011lX, high8: 0x%02X)\n",
                         entry.offset, entry.ptr.raw, entry.ptr.rebase.next, entry.ptr.rebase.target, entry.ptr.rebase.high8);
        }
#endif
    }
    if (rv > 0) {
        goto cleanup;
    }

    size = offsetof(plthook_t, entries) + sizeof(bind_address_t) * num_binds;
    d->plthook = (plthook_t*)calloc(1, size);
    if (d->plthook == NULL) {
        set_errmsg("failed to allocate memory: %" PRIuPTR " bytes", size);
        rv = PLTHOOK_OUT_OF_MEMORY;
        goto cleanup;
    }
    d->plthook->num_entries = num_binds;

    chained_fixups_iter_rewind(&iter);
    num_binds = 0;
    while ((rv = chained_fixups_iter_next(&iter, &entry)) == 0) {
        if (entry.ptr_format == DYLD_CHAINED_PTR_64_OFFSET && entry.ptr.bind.bind) {
            uint16_t ordinal = entry.ptr.bind.ordinal;
            uint32_t name_offset;
            char weak = 0;
            bind_address_t *bind_addr = &d->plthook->entries[num_binds];
#ifdef PLTHOOK_DEBUG_FIXUPS
            int32_t lib_ordinal;
            const char *libname;
#endif
            switch (header->imports_format) {
            case DYLD_CHAINED_IMPORT:
                name_offset = import[ordinal].name_offset;
                weak = import[ordinal].weak_import;
#ifdef PLTHOOK_DEBUG_FIXUPS
                if (import[ordinal].lib_ordinal >= (uint8_t)BIND_SPECIAL_DYLIB_WEAK_LOOKUP) {
                    lib_ordinal = (int8_t)import[ordinal].lib_ordinal;
                } else {
                    lib_ordinal = (uint8_t)import[ordinal].lib_ordinal;
                }
#endif
                break;
            default:
                DEBUG_FIXUPS("imports_format: %u\n", header->imports_format);
                set_errmsg("unsupported imports format %u", header->imports_format);
                rv = PLTHOOK_INTERNAL_ERROR;
                goto cleanup;
            }
            bind_addr->name = symbol_pool + name_offset;
            bind_addr->addr = (void**)fileoff_to_vmaddr(d,  entry.offset);
            bind_addr->addend = entry.ptr.bind.addend;
            bind_addr->weak = weak;
#ifdef PLTHOOK_DEBUG_FIXUPS
            switch (lib_ordinal) {
            case BIND_SPECIAL_DYLIB_SELF:
                libname = "this-image";
                break;
            case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
                libname = "main-executable";
                break;
            case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
                libname = "flat-namespace";
                break;
            case BIND_SPECIAL_DYLIB_WEAK_LOOKUP:
                libname = "weak";
                break;
            default:
                libname = "?";
            }
#endif
            DEBUG_FIXUPS("        %-12s %-16s 0x%08llX              bind  %s/%s",
                         segment_name_from_addr(d, entry.offset), section_name_from_addr(d, entry.offset), entry.offset, libname, symbol_pool + name_offset);
            if (entry.ptr.bind.addend != 0) {
                DEBUG_FIXUPS(" + 0x%X", entry.ptr.bind.addend);
            }
            if (weak) {
                DEBUG_FIXUPS(" [weak-import]");
            }
            DEBUG_FIXUPS("\n");
            num_binds++;
        } else if (entry.ptr_format == DYLD_CHAINED_PTR_64_OFFSET && !entry.ptr.bind.bind) {
            DEBUG_FIXUPS("        %-12s %-16s 0x%08llX            rebase  0x%08llX\n",
                         segment_name_from_addr(d, entry.offset), section_name_from_addr(d, entry.offset), entry.offset, entry.ptr.rebase.target);
        }
    }
    chained_fixups_iter_deinit(&iter);
    rv = 0;
cleanup:
    chained_fixups_iter_deinit(&iter);
    if (rv != 0 && d->plthook) {
        free(d->plthook);
        d->plthook = NULL;
    }
    return rv;
}

#ifdef PLTHOOK_DEBUG_FIXUPS
static const char *segment_name_from_addr(data_t *d, size_t addr)
{
    int i;
    for (i = 0; i < d->num_segments; i++) {
        const struct segment_command_64 *seg = d->segments[i];
        if (seg->fileoff <= addr && addr < seg->fileoff + seg->filesize) {
            return seg->segname;
        }
    }
    return "?";
}

static const char *section_name_from_addr(data_t *d, size_t addr)
{
    int i;
    for (i = 0; i < d->num_sections; i++) {
        const struct section_64 *sec = d->sections[i];
        if (sec->offset <= addr && addr < sec->offset + sec->size) {
            return sec->sectname;
        }
    }
    return "?";
}
#endif

static int set_mem_prot(plthook_t *plthook)
{
    unsigned int pos = 0;
    const char *name;
    void **addr;
    size_t start = (size_t)-1;
    size_t end = 0;
    mach_port_t task = mach_task_self();
    vm_address_t vm_addr = 0;
    vm_size_t vm_size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;
    int idx = 0;

    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        if (start > (size_t)addr) {
            start = (size_t)addr;
        }
        if (end < (size_t)addr) {
            end = (size_t)addr;
        }
    }
    end++;

    while (vm_region_64(task, &vm_addr, &vm_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) == KERN_SUCCESS) {
        mem_prot_t mem_prot = {vm_addr, vm_addr + vm_size, info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC)};
        if (mem_prot.prot != 0 && mem_prot.start < end && start < mem_prot.end) {
            plthook->mem_prot[idx++] = mem_prot;
            if (idx == NUM_MEM_PROT) {
                break;
            }
        }
        vm_addr += vm_size;
    }
    return 0;
}

static int get_mem_prot(plthook_t *plthook, void *addr)
{
    mem_prot_t *ptr = plthook->mem_prot;
    mem_prot_t *end = ptr + NUM_MEM_PROT;

    while (ptr < end && ptr->prot != 0) {
        if (ptr->start <= (size_t)addr && (size_t)addr < ptr->end) {
            return ptr->prot;
        }
        ++ptr;
    }
    return 0;
}

static uint8_t *fileoff_to_vmaddr(data_t *d, size_t offset)
{
    int i;
    for (i = 0; i < d->num_segments; i++) {
        const struct segment_command_64 *seg = d->segments[i];
        if (seg->fileoff <= offset && offset < seg->fileoff + seg->filesize) {
            return fileoff_to_vmaddr_in_segment(d, i, offset);
        }
    }
    return NULL;
}

int plthook_enum(plthook_t *plthook, unsigned int *pos, const char **name_out, void ***addr_out)
{
    plthook_entry_t entry;
    int rv = plthook_enum_entry(plthook, pos, &entry);
    if (rv == 0) {
        *name_out = entry.name;
        *addr_out = entry.addr;
    }
    return rv;
}

int plthook_enum_with_prot(plthook_t *plthook, unsigned int *pos, const char **name_out, void ***addr_out, int *prot)
{
    plthook_entry_t entry;
    int rv = plthook_enum_entry(plthook, pos, &entry);
    if (rv == 0) {
        *name_out = entry.name;
        *addr_out = entry.addr;
        if (prot) {
            *prot = entry.prot;
        }
    }
    return rv;
}

int plthook_enum_entry(plthook_t *plthook, unsigned int *pos, plthook_entry_t *entry)
{
    memset(entry, 0, sizeof(*entry));
    while (*pos < plthook->num_entries) {
        if (strcmp(plthook->entries[*pos].name, "__tlv_bootstrap") == 0) {
            (*pos)++;
            continue;
        }
        entry->name = plthook->entries[*pos].name;
        entry->addr = plthook->entries[*pos].addr;
        entry->addend = plthook->entries[*pos].addend;
        entry->prot = get_mem_prot(plthook, entry->addr);
        entry->weak = plthook->entries[*pos].weak;
        (*pos)++;
        return 0;
    }
    return EOF;
}

int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc)
{
    size_t funcnamelen = strlen(funcname);
    unsigned int pos = 0;
    plthook_entry_t entry;
    int rv;

    if (plthook == NULL) {
        set_errmsg("invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }
    while ((rv = plthook_enum_entry(plthook, &pos, &entry)) == 0) {
        const char *name = entry.name;
        void **addr = entry.addr;
        if (strncmp(name, funcname, funcnamelen) == 0) {
            if (name[funcnamelen] == '\0' || name[funcnamelen] == '$') {
                goto matched;
            }
        }
        if (name[0] == '@') {
            /* I doubt this code... */
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
        if (!(entry.prot & PROT_WRITE)) {
            size_t page_size = sysconf(_SC_PAGESIZE);
            void *base = (void*)((size_t)addr & ~(page_size - 1));
            if (mprotect(base, page_size, PROT_READ | PROT_WRITE) != 0) {
                set_errmsg("Cannot change memory protection at address %p", base);
                return PLTHOOK_INTERNAL_ERROR;
            }
            *addr = funcaddr;
            mprotect(base, page_size, entry.prot);
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
