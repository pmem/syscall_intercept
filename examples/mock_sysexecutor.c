#define _GNU_SOURCE // Required for syscall
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    // Define syscall number and arguments
    long syscall_number = 257;
    long arg0 = 4294967196;
    long arg1 = 94032706248712;
    long arg2 = 2987237386;
    long arg3 = 0;
    long arg4 = 140506023702288;
    long arg5 = 140506024349760;

    // Execute the syscall
    long result = syscall(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);

    if (result == -1) {
        perror("syscall");
        return 1;
    }

    // Print the result of the syscall
    printf("Result of syscall %ld: %ld\n", syscall_number, result);

    return 0;
}
