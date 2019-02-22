#include <cstdlib>
#include <cstdio>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>

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

/* number of bytes allocated for the executable memory */
static const unsigned int virt_bytes = 4096;
/* location of executable memory */
static void *virt = NULL;
/* byte addressable executable memory */
static unsigned char *byte = NULL;
/* entry function into the assembly */
typedef void (*assembly) (void *addr);

/* 
 * Write a nop slide to safely exit the assembly section to start handling the
 * next Program generated.
 */
static void
segfault_handler (int sig, siginfo_t *info, void *u)
{
    struct ucontext_t *context = (struct ucontext_t*) u;
    /* 
     * struct mcontext_t is machine dependent and opaque on purpose. It is used
     * for restoring the context and we could increment the REG_RIP value and
     * that would skip to the next instruction (but that could be bad). We 
     * instead use it to know if the faulting instruction is in the expected
     * location.
     */
    long long fault_addr = context->uc_mcontext.gregs[REG_RIP];
    long long assem_addr = (long long) virt;

    if (sig != SIGSEGV)
        return;

    /* TODO: doing IO in signal handlers is bad, but ... */
    if (fault_addr < assem_addr || fault_addr > assem_addr + virt_bytes) {
        printf("Segfault\n");
        exit(1);
    }

    printf("caught segfault at %llx. bad memory address %p. virt %llx\n", 
            fault_addr, info->si_call_addr, assem_addr);
    /* write nops for the entire buffer */
    memset(virt, 0x90, virt_bytes);
    /* ret instruction for last byte */
    byte[virt_bytes-1] = 0xc3;
}

int main(int argc, char *argv[])
{
    struct sigaction sa;
    int value = 42;
    assembly func;

    virt = mmap(NULL, virt_bytes,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_ANONYMOUS | MAP_PRIVATE,
                0, 0);
    byte = (unsigned char *) virt;
    func = (assembly) virt;

    /* Catch segfault signal */
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    /*
     *  movq    $1337, %(rdi)
     *  ret
     */
    byte[0] = 0x48;
    byte[1] = 0xc7;
    byte[2] = 0x07;
    byte[3] = 0x39;
    byte[4] = 0x05;
    byte[5] = 0x00;
    byte[6] = 0x00;
    byte[7] = 0xc3;

    printf("before: %d\n", value);
    func(&value);
    printf("after: %d\n", value);

    /* test segfault */
    char *b = NULL;
    *b = 5;

    return 0;
}
