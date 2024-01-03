#include <stdio.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>
#include <string.h>

#define VMADDR_CID_HOST 2   // The CID for the host
#define VSOCK_PORT 5000     // The VSOCK port to connect to

int main() {
    int sock;
    struct sockaddr_vm server = {0};
    char message[1024], server_reply[1024];

    // Create a VSOCK socket
    sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
        return 1;
    }
    puts("Socket created");

    server.svm_family = AF_VSOCK;
    server.svm_cid = VMADDR_CID_HOST; // CID for the host
    server.svm_port = VSOCK_PORT;     // VSOCK port

    // Connect to the VSOCK server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    // Communicate with server
    printf("Enter message: ");
    scanf("%s", message);

    // Send some data
    if (send(sock, message, strlen(message), 0) < 0) {
        puts("Send failed");
        return 1;
    }

    // Receive a reply from the server
    if (recv(sock, server_reply, 1024, 0) < 0) {
        puts("recv failed");
        return 1;
    }

    puts("Server reply:");
    puts(server_reply);

    close(sock);
    return 0;
}
