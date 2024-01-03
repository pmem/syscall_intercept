#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOST "127.0.0.1"
#define PORT 7000
#define INTERVAL 5 // Interval in seconds

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char message[] = "Hello from client";
    char buffer[1024];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket creation failed");
        return 1; // Return non-zero if socket creation failed
    }

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(HOST);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1; // Return non-zero if connection failed
    }
    printf("Connected");

    // Send message
    if (send(sock, message, strlen(message), 0) < 0) {
        perror("send failed");
        close(sock);
        return 1; // Return non-zero if send failed
    }

    // Clear buffer and receive response
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
        close(sock);
        return 1; // Return non-zero if receive failed
    } else if (bytes_received == 0) {
        printf("Server closed the connection\n");
        close(sock);
        return 0; // Return zero as server closed connection gracefully
    } else {
        printf("Received: %s\n", buffer);
    }

    // Close socket as response is successfully received
    close(sock);
    return 0; // Return zero as response is successfully received
}
