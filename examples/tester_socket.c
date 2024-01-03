#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sock;
    struct sockaddr_in server;
    char message[1024], server_reply[1024];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(7000); // Connect to the host port routed by socat

    // Connect to remote server
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
