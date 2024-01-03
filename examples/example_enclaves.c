#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <json-c/json.h>
#include <syscall.h>
#include <errno.h>
#include <libsyscall_intercept_hook_point.h>
#include <linux/vm_sockets.h> // For vsock


#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7000

int socket_fd = 0;

int user_event_open(const char *path, int operation) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": %d, \"filename\": \"%s\"}\n", operation, path);
    send(socket_fd, jsonStr, strlen(jsonStr), 0);

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = recv(socket_fd, &response_int, sizeof(response_int), 0);
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);  // Wait 100 milliseconds
    }
    return 0;
}

int user_event_write(unsigned int fd, const char *buf, size_t count) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": 2, \"file_descriptor\": %d, \"data\": \"%s\"}\n", fd, buf);
    send(socket_fd, jsonStr, strlen(jsonStr), 0);

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = recv(socket_fd, &response_int, sizeof(response_int), 0);
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);  // Wait 100 milliseconds
    }
    return 0;
}

int user_event_delete(const char *path, int operation){
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": %d, \"filename\": \"%s\"}\n", operation, path);
    send(socket_fd, jsonStr, strlen(jsonStr), 0);

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = recv(socket_fd, &response_int, sizeof(response_int), 0);
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);  // Wait 100 milliseconds
    }
    return 0;
}

int user_event_read(unsigned int fd, const char *buf, size_t count){
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": 4, \"file_descriptor\": %d, \"data\": \"%s\"}\n", fd, buf);
    send(socket_fd, jsonStr, strlen(jsonStr), 0);

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = recv(socket_fd, &response_int, sizeof(response_int), 0);
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);  // Wait 100 milliseconds
    }
    return 0;
}

static int my_hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result) {
    if (syscall_number == SYS_openat) {
        *result = user_event_open((const char *)arg1, 1);
        return 0;
    } else if (syscall_number == SYS_write) {
        char buf_copy[0x1000];
        size_t size = (size_t)arg2;
        if (size > sizeof(buf_copy)) {
            size = sizeof(buf_copy);
        }
         memcpy(buf_copy, (const char *)arg1, size);
        *result = user_event_write((unsigned int)arg0, buf_copy, size);
        return 0;
    } else if (syscall_number == SYS_unlink){
        *result = user_event_delete((const char *)arg0, 3);
        return 0;
    } else if (syscall_number == SYS_read){
        char buf_copy[0x1000];
        size_t size = (size_t)arg2;
        if (size > sizeof(buf_copy)) {
            size = sizeof(buf_copy);
        }
         memcpy(buf_copy, (const char *)arg1, size);
        *result = user_event_write((unsigned int)arg0, buf_copy, size);
        return 0;
    }

    return 1;
}

static void setup_socket() {
    struct sockaddr_in server_addr = {0};

    // Create a VSOCK socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
       printf("error");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the vsock port of the host
    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
       printf("error");
      }
}

static __attribute__((constructor)) void init(void) {
    setup_socket();
    intercept_hook_point = my_hook;
}
