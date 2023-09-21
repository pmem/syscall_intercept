#include <stdio.h>
#include <stdlib.h>

int main() {
    // Use the system function to execute the 'ls' command
    int returnCode = system("ls");

    // Check if the command executed successfully
    if (returnCode == 0) {
        printf("Command executed successfully.\n");
    } else {
        printf("Command failed with exit code %d\n", returnCode);
    }

    return 0;
}
