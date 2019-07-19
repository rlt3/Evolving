#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

void
payload (void *val)
{
    asm(
        "movq $7331, (%rdi)\n"
    );
}

void
payload_end ()
{
}

void
scanhex (char *input, uint32_t *output)
{
    if (sscanf(input, "0x%x", output) < 1) {
        perror(strerror(errno));
        exit(1);
    }
}

int
main (int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <executable> <start> <end> <key>\n", argv[0]);
        exit(1);
    }

    FILE *f = NULL;
    uint32_t start = 0;
    uint32_t end = 0;
    uint32_t len = 0;
    uint32_t key = 0;

    f = fopen(argv[1], "r+");
    if (!f) {
        perror(strerror(errno));
        exit(1);
    }

    scanhex(argv[2], &start);
    scanhex(argv[3], &end);
    scanhex(argv[4], &key);
    len = end - start + 1;

    /* read the bytes we are 'encrypting' */
    fseek(f, start, SEEK_CUR);
    uint8_t bytes[len];
    fread(bytes, len, 1, f);

    /* print out the indivdual bytes and XOR them */
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
        bytes[i] ^= key;
    }
    putchar('\n');

    /* finally write the bytes */
    rewind(f);
    fseek(f, start, SEEK_CUR);
    fwrite(bytes, len, 1, f);

    fclose(f);
    return 0;
}
