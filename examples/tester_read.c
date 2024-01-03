#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    char filename[] = "/home/atello/bcc/examples/test.txt";
    char buffer[1024];  // Buffer to hold file content

    // Open the file
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    // Read and display the file contents
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }

    // Close the file
    fclose(file);

    return EXIT_SUCCESS;
}
