#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdint.h>

void
landing (void *val)
{
    asm(
        "movq $1337, (%rdi)\n"
    );
}

void
landing_end ()
{
    /* Meant to be empty -- simply marks the end of the landing */
}

void*
getpage (void *p, uint64_t size)
{
    return (void*)((uint64_t)p & ~(size - 1));
}

int
main (int argc, char **argv)
{
    uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
    void* page = getpage(landing, pagesize);

    printf("%p\n", page);
    printf("%lu\n", pagesize);

    if (mprotect(page, pagesize, PROT_WRITE | PROT_EXEC | PROT_READ) < 0) {
        perror(strerror(errno));
        exit(1);
    }

    //uint8_t payload[] = {
    //    0x55,
    //    0x48, 0x89, 0xe5,
    //    0x48, 0x89, 0x7d, 0xf8,
    //    0x48, 0xc7, 0x07, 0xa3, 0x1c, 0x00, 0x00,
    //    0x90,
    //    0x5d,
    //    0xc3
    //};
    //uint32_t payload_len = sizeof(payload);
    //memcpy(landing, payload, payload_len);

    int val = 1;
    landing(&val);
    printf("landing: %d\n", val);

    return 0;
}
