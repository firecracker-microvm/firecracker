#include <sys/io.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_ARGN 10

int main(int argc, char **argv)
{
    pid_t child_pid;
    int status = 0;
    char *args[MAX_ARGN] = {"sh"};

    if((child_pid = fork()) == 0) {
        execv("/bin/busybox", args);
    } else {
        wait(&status);
        iopl(3);
        outb(0xfe, 0x64);
    }

    return 0;
}
