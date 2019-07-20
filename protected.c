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
landing ()
{
    /* 
     * Using a string literal here like s = "foobar" would cause the compiler
     * to put the string "foobar" into a different section of memory. But we
     * want to encrypt everything inside this area. So instead we construct the
     * string as an array of bytes so the compiler cannot place it into a
     * different section.
     */
    char s[] = {'h', 'e', 'l', 'l', 'o', '\0'};
    char format[] = {'%', 's', '\n', '\0'};
    printf(format, s);
}

void
landing_end ()
{
    /* 
     * Meant to be empty -- simply marks the end of the landing section so that
     * we can properly get the correct length of the landing section.
     */
}

void*
getpage (void *p, uint64_t size)
{
    return (void*)((uint64_t)p & ~(size - 1));
}

int
main (int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <key>\n", argv[0]);
        exit(1);
    }

    uint32_t key = 0;
    if (sscanf(argv[1], "0x%x", &key) < 1) {
        fprintf(stderr, "Argument `%s' needs to be a hexadecimal!\n", argv[1]);
        exit(1);
    }

    /*
     * The mprotect system call *must* be called on an address that is page
     * aligned and *must* be the length of the entire page. The `getpage`
     * function simply uses bit-arithmetic to clear the least significant bits
     * for the size of a page. This allows us to write to this program's
     * instructions which are normally read/execute only.
     */
    uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
    void* page = getpage(landing, pagesize);
    if (mprotect(page, pagesize, PROT_WRITE | PROT_EXEC | PROT_READ) < 0) {
        perror(strerror(errno));
        exit(1);
    }

    /*
     * Read from the landing the encrypted bytes, decrypt them using the
     * given key, and write them back to the landing.
     */
    uint64_t payload_len = landing_end - landing;
    uint8_t *payload = (void*) landing;
    for (int i = 0; i < payload_len; i++)
        payload[i] ^= key;
    memcpy(landing, payload, payload_len);

    /* Finally, run the protected segment */
    landing();
    return 0;
}
