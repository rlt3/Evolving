#include <cstdlib>
#include <cstdio>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>

enum INST {
    MOV,
    ADD,
    RET
};

enum ARG {
    REG,
    ADDR,
    IMM
};

class Instruction {
    static void
    write ()
    {
        /* 
         * single static method for all Instructions that writes the produces
         * the instruction's bytes.
         */
    }
};

/*
 * A program that can be written to executable memory and executed.
 */
class Program {
};

static const unsigned int num_bytes = 4096;
static void *virt = NULL;
unsigned char *byte = NULL;

/* 
 * Write a nop slide to safely exit the assembly section to start handling the
 * next Program generated.
 * TODO: would be cool if somehow I could get the pc of the instruction that
 * caused the segfault rather than the access'd memory address. This way I can
 * test that the instruction came from the assembly section of mmap'd memory.
 */
static void
segfault_handler (int sig, siginfo_t *info, void *context)
{
    if (sig != SIGSEGV)
        return;
    printf("caught segfault at %p\n", info->si_addr);
    /* write nops for the entire buffer */
    memset(virt, 0x90, num_bytes);
    /* ret instruction for last byte */
    byte[num_bytes-1] = 0xc3;
}

typedef void (*assembly) (void);

int main(int argc, char *argv[])
{
   int value = 42;
   unsigned long addr = (unsigned long) &value;

   virt = mmap(NULL, num_bytes,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_ANONYMOUS | MAP_PRIVATE,
                0, 0);
   byte = (unsigned char *) virt;

   /* Catch segfault signal */
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    printf("virt = %p, addr = 0x%lx\n", virt, addr);

    /*
     * movl    $1337, %eax
     * movl    %eax, <addr>
     * ret
     */
    byte[0] = 0xb8;
    byte[1] = 0x39;
    byte[2] = 0x05;
    byte[3] = 0x00;
    byte[4] = 0x00;
    byte[5] = 0xa3;
    for (unsigned i = 0; i < sizeof(addr); i++) {
       byte[i+6] = 0xff; /* write a bad address to write to */
       //byte[i+6] = (addr >> (8 * i)) & 0xff;
    }
    byte[14] = 0xc3;

    for (int i = 0; i < 15; i++)
        printf("%2x ", byte[i]);
    printf("\n");

    /* 
     * mov $1337, %eax
     * ret
     */
    //c[0] = 0xB8;
    //c[1] = 0x39;
    //c[2] = 0x05;
    //c[3] = 0x00;
    //c[4] = 0x00;
    //c[5] = 0xC3;

    printf("before: %d\n", value);
    assembly func = (assembly) virt;
    func();
    printf("after: %d\n", value);

    return 0;
}
