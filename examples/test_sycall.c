#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    // Syscall number and arguments for openat
    long syscall_number = __NR_openat;
    long dirfd = 4294967196;
    long pathname = 94043072761892;
    long flags = 468848678;
    long mode = 0;

    long result; // Variable to store the syscall result

    // Set up registers and invoke the syscall
    asm volatile (
        "movq %[syscall_number], %%rax\n\t" // syscall number in RAX
        "movq %[dirfd], %%rdi\n\t"         // dirfd in RDI
        "movq %[pathname], %%rsi\n\t"     // pathname in RSI
        "movq %[flags], %%rdx\n\t"         // flags in RDX
        "movq %[mode], %%r10\n\t"          // mode in R10
        "syscall\n\t"
        : "=a" (result)
        : [syscall_number] "g" (syscall_number), [dirfd] "g" (dirfd),
          [pathname] "g" (pathname), [flags] "g" (flags), [mode] "g" (mode)
        : "rdi", "rsi", "rdx", "r10", "memory"
    );

    if (result >= 0) {
        printf("syscall result: %ld\n", result);
    } else {
        perror("syscall error found");
    }

    return 0;
}
