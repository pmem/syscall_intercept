#include <stdio.h>
#include <libsyscall_intercept_hook_point.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <json-c/json.h>
#include <syscall.h>
#include <errno.h>


// Replace with your actual server's IP and port
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

int socket_fd;

int user_event(const char *path, int operation) {
    // Implement your logic here. For example, send path and flags to a server.
  /* json_object *jobj = json_object_new_object();
   json_object_object_add(jobj, "operation", json_object_new_int(operation));
   json_object_object_add(jobj, "filename", json_object_new_string(path));

    // Convert JSON object to a string
    const char *jsonStr = json_object_to_json_string(jobj);*/
    char jsonStr[1024];

    // Manually format the JSON string
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": %d, \"filename\": \"%s\"}", operation, path);
    strncat(jsonStr, "\n", sizeof(jsonStr) - strlen(jsonStr) - 1);
    //printf("Sending JSON to server: %s\n", jsonStr);

    // Send JSON string over the socket
    send(socket_fd, jsonStr, strlen(jsonStr), 0);

    // Free memory allocated for JSON object
   //json_object_put(jobj);
    unsigned int response_int;
    int bytes_received = recv(socket_fd, &response_int, sizeof(response_int), 0);
    if (bytes_received > 0) {
        // Convert from network byte order to host byte order
        response_int = ntohl(response_int);
        printf("Response received from server: %d\n", response_int);
        return response_int;
    } else if (bytes_received == 0) {
        printf("Server closed the connection\n");
    } else {
        perror("recv failed");
    }
    return 0;
 }

int setup_socket() {
    struct sockaddr_in server_addr;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) return -1;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        return -1;

    return 0;
}

int main(void) {
    // Setup the socket connection
    if (setup_socket() < 0) {
        perror("Socket setup failed");
        return 1;
    }
        const char *path = "test";
        int operation = 1;

        // Trigger your user event
        user_event(path, operation);


    close(socket_fd);

    return 0;
}
