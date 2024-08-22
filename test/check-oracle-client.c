#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <plthook.h>

typedef signed int sword;

void OCIClientVersion(sword *featureRelease,
                      sword *releaseUpdate,
                      sword *releaseUpdateRevision,
                      sword *increment,
                      sword *ext);

static int check_import_addresses(plthook_t *ph)
{
    unsigned int pos = 0;
    plthook_entry_t entry;
    int cnt;
    int err = 0;

    fprintf(stderr, "Checking import addresses\n");
    while (plthook_enum_entry(ph, &pos, &entry) == 0) {
        cnt++;
        void *symaddr = dlsym(RTLD_DEFAULT, entry.name + 1);
#if 0
        Dl_info info;
        if (dladdr(symaddr, &info)) {
            fprintf(stderr, "%s,%s:%s,", entry.name + 1, info.dli_fname, info.dli_sname);
        } else {
            fprintf(stderr, "dladdr error: %s - ,", dlerror());
        }
        if (dladdr(*entry.addr, &info)) {
            fprintf(stderr, "%s:%s+0x%llx\n", info.dli_fname, info.dli_sname, (size_t)*entry.addr - (size_t)info.dli_saddr);
        } else {
            fprintf(stderr, "dladdr error: %s\n", dlerror());
        }
#endif
        if ((size_t)*entry.addr != (size_t)symaddr + entry.addend) {
            if (entry.addend) {
                fprintf(stderr, "%p:%p:%p:%s + 0x%x\n", entry.addr, *entry.addr, symaddr, entry.name, entry.addend);
            } else {
                fprintf(stderr, "%p:%p:%p:%s\n", entry.addr, *entry.addr, symaddr, entry.name);
            }
            err++;
        }
    }
    fprintf(stderr, "number of entries: %d\n", cnt);
    return (err || cnt == 0) ? 1 : 0;
}

int main()
{
    sword ver[5];
    OCIClientVersion(&ver[0], &ver[1], &ver[2], &ver[3], &ver[4]);
    fprintf(stderr, "Oracle Client Version: %d.%d.%d.%d.%d\n", ver[0], ver[1], ver[2], ver[3], ver[4]);

    void *symaddr = dlsym(RTLD_DEFAULT, "OCIClientVersion");
    if (symaddr == NULL) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        return 1;
    }
    plthook_t *ph;
    if (plthook_open_by_address(&ph, symaddr) != 0) {
        fprintf(stderr, "plthook_open error: %s\n", plthook_error());
        return 1;
    }
    if (check_import_addresses(ph) != 0) {
        return 1;
    }
    plthook_close(ph);
    return 0;
}
