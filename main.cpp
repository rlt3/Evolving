#include <cstdlib>
#include <cstdio>
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

typedef void (*assembly) (void);

int main(int argc, char *argv[])
{
   // probably needs to be page aligned...
   unsigned int num_bytes = 4096;
   unsigned char *byte = NULL;
   void *virt = NULL;

   int value = 42;
   unsigned long addr = (unsigned long) &value;

   virt = mmap(NULL, num_bytes,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_ANONYMOUS | MAP_PRIVATE,
                0, 0);
   byte = (unsigned char *) virt;

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
       byte[i+6] = (addr >> (8 * i)) & 0xff;
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
