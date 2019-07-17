#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdint.h>

typedef void (*entry_func) (void *addr);
typedef void (*sig_handler_func) (int, siginfo_t*, void*);

static const uint32_t SEG_LEN = 128;
static void* SEG = 0;

/* Set the signal handler to the given func */
void
set_signal_handler (void* func)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = (sig_handler_func) func;
    sa.sa_flags = SA_SIGINFO;

    /* Catch the segfault and illegal instruction signals */
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

/* Set the permissions over an allocated segment */
void
set_permissions (const uint32_t protections)
{
    /* 
     * We always want the segment to be readable. We do want both writable and 
     * executable as the instructions could malform themselves while executing.
     */
    if (mprotect(SEG, SEG_LEN, protections | PROT_READ) < 0) {
        perror(strerror(errno));
        exit(1);
    }
}

void
write_instructions (uint8_t *bytes, uint32_t length)
{
    set_permissions(PROT_WRITE);
    memset(SEG, 0, SEG_LEN);
    memcpy(SEG, bytes, length);
}

void
exec_instructions (void *data)
{
    set_permissions(PROT_EXEC);
    entry_func f = (entry_func) SEG;
    f(data);
}

/* Write a nop slide to safely exit from the malformed instructions */
static void
catch_malformed_instructions (int sig, siginfo_t *info, void *u)
{
    assert((sig == SIGSEGV || sig == SIGILL));
    assert(SEG && SEG_LEN > 0);

    /* 
     * struct mcontext_t is machine dependent and opaque on purpose. It is
     * used for restoring the context and we could increment the REG_RIP
     * value and that would skip to the next instruction (but that could be
     * bad). We instead use it to know if the faulting instruction is in
     * the expected location.
     */
    ucontext_t *context = (ucontext_t*) u;
    uint64_t fault_addr = context->uc_mcontext.gregs[REG_RIP];

    /* 
     * If the signal is a real one (not caused by our mutation memory segment)
     * then set the signal back to default (SIG_DFL) and return, letting the
     * program's instruction raise the signal again naturally.
     */
    if (fault_addr < (uint64_t) SEG || fault_addr > (uint64_t)SEG + SEG_LEN) {
        set_signal_handler((void*) SIG_DFL);
        return;
    }

    printf("caught signal %d at %p. bad memory address %p. virt %p\n", 
            sig, (void*) fault_addr, info->si_call_addr, SEG);

    /* Otherwise write the nop slide with a ret at the end */
    uint8_t bytes[SEG_LEN];
    /* write nops for the entire buffer */
    memset(bytes, 0x90, SEG_LEN);
    /* ret instruction for last byte */
    write_instructions(bytes, SEG_LEN);
    /* 
     * execution will automatically begin after this function returns, so make
     * sure the segment is marked as executable.
     */
    set_permissions(PROT_EXEC);
}

int
main (int argc, char *argv[])
{
    SEG = mmap(NULL, SEG_LEN,
                    PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE,
                    0, 0);
    if (!SEG) {
        perror(strerror(errno));
        exit(1);
    }

    set_signal_handler((void*) catch_malformed_instructions);

    uint8_t byte[SEG_LEN];
    int value = 42;

    /*
     *  movq    $1337, %(rdi)
     *  ret
     */
    byte[0] = 0x44;
    byte[1] = 0xc7;
    byte[2] = 0x07;
    byte[3] = 0x39;
    byte[4] = 0x05;
    byte[5] = 0x00;
    byte[6] = 0x00;
    byte[7] = 0xc3;

    write_instructions(byte, 8);
    printf("before: %d\n", value);
    exec_instructions(&value);
    printf("after: %d\n", value);

    /* test segfault */
    //char *b = NULL;
    //*b = 5;

    return 0;
}
