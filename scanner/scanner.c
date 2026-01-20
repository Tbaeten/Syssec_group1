#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
// scans one memory region in its range [start, end]
// looks for byte patterns 0x0F05
//perms = permission strings
static void scan_region(uintptr_t start, uintptr_t end, const char *perms, const char *path) {
    unsigned char *p = (unsigned char *)start;
    unsigned char *q = (unsigned char *)end;

    for (; p + 1 < q; p++) { //loop through the bytes in the region
        if (p[0] == 0x0f && p[1] == 0x05) { //syscall is 2 bytes
            printf("syscall at %p in region 0x%lx-0x%lx %s %s\n",
                   (void*)p,
                   (unsigned long)start,
                   (unsigned long)end,
                   perms,
                   path ? path : "");
        }
    }
}

//function that runs automatically when the library is loaded
__attribute__((constructor))
static void init_scanner() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        perror("fopen /proc/self/maps");
        return;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) { //read line by line from the memory mapping of the process
        uintptr_t start = 0, end = 0;
        char perms[5] = {0}; //e.g. r-xp + NULL = 5 chars
        char path[2048] = {0};

        // parse: start-end perms offset dev inode [path]
        // path is optional
       // address           perms offset  dev   inode   pathname
        //08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
        //read two hex nr (start, end), read perm, ignore offset, dev, inode and read pathname
        int n = sscanf(line, "%lx-%lx %4s %*s %*s %*s %2047[^\n]", 
                       (unsigned long *)&start,
                       (unsigned long *)&end,
                       perms,
                       path);

        if (n < 3) continue;

        // skip line if not executable
        if (strchr(perms, 'x') == NULL) continue;
        // skip line if not readable
        if (perms[0] != 'r') continue;
        scan_region(start, end, perms, (n == 4 ? path : ""));
    }

    fclose(f);
}