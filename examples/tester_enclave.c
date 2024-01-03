#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>


int main() {
    setenv("INTERCEPT_LOG", "'intercept.log-'", 1);

    const char *directory = "/home/ec2-user/dev/aws-nitro-enclaves-samples/syscall_interceptor";
    const char *file_name = "test.txt";
    printf("Test");
    int file_descriptor;

    // Flags for the openat syscall
    int flags = O_WRONLY;

    // Prepare the file path combining directory and file name
    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/%s", directory, file_name);

    // Call the openat syscall with the correct file path
    file_descriptor = openat(AT_FDCWD, file_path, flags);

    // Check if the openat syscall was successful
    if (file_descriptor >= 0) {

        const char *data_to_write = "testing from client";
        ssize_t bytes_written = write(file_descriptor, data_to_write, strlen(data_to_write));

        if (bytes_written < 0) {
            perror("Error writing to file");
        }else{

        }
        close(file_descriptor);
    } else {
        perror("Error opening file");
    }
    remove("/home/atello/bcc/examples/test2.txt");
    return 0;
}
