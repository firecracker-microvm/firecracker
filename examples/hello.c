#include <sys/io.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    printf("hello, world!\n");
    iopl(3);
    outb(0xfe, 0x64);

    return 0;
}
