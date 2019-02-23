#pragma once

#include <cstdlib>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdint.h>

/* entry function into the assembly */
typedef void (*assembly) (void *addr);
typedef void (*segment_sig_handler) (int, siginfo_t*, void*);

/*
 * Create and manage a memory segment that is both executable and writable with
 * signal handlers to prevent the segment from crashing the program.
 */
class Segment {
public:
    /* 
     * Starting and ending addresses of currently executing segment. This allow
     * for signal handling multiple executable segment objects, but only in a
     * single-threaded environment. Would need to upgrade this data-structure
     * to allow for multiple threads with signal handling.
     */
    static uint64_t addr_beg;
    static uint64_t addr_end;

    /*
     * By default, the length of a segment is the length of a page size because
     * executable memory must be page aligned. Next step (if needed) is to have
     * a constructor which defines multiples of the pagesize as the length.
     */
    Segment ()
        : seg_len(getpagesize())
    {
        seg = mmap(NULL, seg_len,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE,
                    0, 0);
        if (!seg) {
            perror(strerror(errno));
            exit(1);
        }
        Segment::set_signal_handler((void*) Segment::signal_handler);
    }

    /* Reset the signal handler to its default actions */
    ~Segment ()
    {
        Segment::set_signal_handler((void*) SIG_DFL);
    }

    /* Set memory segment to WRITE and write to it, clearing it first */
    void
    write (uint8_t *bytes, uint32_t length)
    {
        Segment::set_prot(seg, seg_len, PROT_WRITE);
        memset(seg, 0, seg_len);
        memcpy(seg, bytes, length);
    }

    /* Set memory segment to EXEC and execute */
    void
    exec (void *data)
    {
        Segment::set_prot(seg, seg_len, PROT_EXEC);
        Segment::addr_beg = (uint64_t) seg;
        Segment::addr_end = addr_beg + seg_len;
        assembly func = (assembly) seg;
        func(data);
        Segment::addr_beg = 0;
        Segment::addr_end = 0;
    }

    /* Write a nop slide to safely exit the malformed assembly section */
    static void
    signal_handler (int sig, siginfo_t *info, void *u)
    {
        ucontext_t *context = (ucontext_t*) u;
        /* 
         * struct mcontext_t is machine dependent and opaque on purpose. It is
         * used for restoring the context and we could increment the REG_RIP
         * value and that would skip to the next instruction (but that could be
         * bad). We instead use it to know if the faulting instruction is in
         * the expected location.
         */
        uint64_t fault_addr = context->uc_mcontext.gregs[REG_RIP];
        uint32_t len = Segment::addr_end - Segment::addr_beg;
        uint8_t *seg = (uint8_t *) Segment::addr_beg;
        assert((sig == SIGSEGV || sig == SIGILL));

        /* 
         * If the signal is a real one (not caused by our mutation memory
         * segment) then remove the handler and return, letting the program's
         * instruction raise the signal again naturally.
         */
        if (fault_addr < Segment::addr_beg || fault_addr > Segment::addr_end) {
            Segment::set_signal_handler((void*) SIG_DFL);
            return;
        }

        printf("caught signal %d at %p. bad memory address %p. virt %p\n", 
                sig, (void*) fault_addr, info->si_call_addr, (void*) Segment::addr_beg);

        assert(seg && len > 0);
        Segment::set_prot(seg, len, PROT_WRITE);
        /* write nops for the entire buffer */
        memset(seg, 0x90, len);
        /* ret instruction for last byte */
        seg[len - 1] = 0xc3;
        Segment::set_prot(seg, len, PROT_EXEC);
    }

protected:

    static void
    set_prot (void* seg, const uint32_t len, const uint32_t protections)
    {
        if (mprotect(seg, len, protections | PROT_READ) < 0) {
            perror(strerror(errno));
            exit(1);
        }
    }

    static void
    set_signal_handler (void *handler)
    {
        /* Catch segfault and sigill signals */
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = (segment_sig_handler) handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
    }

    /* number of bytes allocated for the executable memory */
    uint32_t seg_len;
    /* location of executable memory */
    void *seg;
};

uint64_t Segment::addr_beg = 0;
uint64_t Segment::addr_end = 0;
