#include <cstdio>
#include "Segment.hpp"

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

int main(int argc, char *argv[])
{
    Segment mem;
    uint8_t byte[4096];
    int value = 42;

    /*
     *  movq    $1337, %(rdi)
     *  ret
     */
    byte[0] = 0x88;
    byte[1] = 0xc7;
    byte[2] = 0x07;
    byte[3] = 0x39;
    byte[4] = 0x05;
    byte[5] = 0x00;
    byte[6] = 0x00;
    byte[7] = 0xc3;

    mem.write(byte, 8);

    printf("before: %d\n", value);
    mem.exec(&value);
    printf("after: %d\n", value);

    /* test segfault */
    //char *b = NULL;
    //*b = 5;

    return 0;
}
