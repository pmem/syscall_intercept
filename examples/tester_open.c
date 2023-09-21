#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    setenv("INTERCEPT_LOG", "intercept.log", 1);

    const char *directory = ".";
    const char *file_name = "CMakeLists.txt";
    int file_descriptor;

    // Flags for the openat syscall
    int flags = O_RDONLY;

    // Call the openat syscall
    file_descriptor = openat(AT_FDCWD, directory, file_name, flags);

    // Check if the openat syscall was successful
    if (file_descriptor >= 0) {
        printf("File opened successfully with file descriptor %d\n", file_descriptor);
        // You can perform additional operations with the opened file descriptor here
        close(file_descriptor);
    } else {
        perror("Error opening file");
    }

    return 0;
}
