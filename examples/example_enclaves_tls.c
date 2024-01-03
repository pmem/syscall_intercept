#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json-c/json.h>
#include <syscall.h>
#include <errno.h>
#include <libsyscall_intercept_hook_point.h>
#include <linux/vm_sockets.h>

#define SERVER_IP "35.158.113.201"
#define SERVER_PORT 50051

SSL_CTX *sslctx;
SSL *ssl;
int socket_fd = 0;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int user_event_open(const char *path, int operation) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": %d, \"filename\": \"%s\"}\n", operation, path);
    SSL_write(ssl, jsonStr, strlen(jsonStr));
    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = SSL_read(ssl, &response_int, sizeof(response_int));
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);
    }
    return 0;
}

int user_event_write(unsigned int fd, const char *buf, size_t count) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": 2, \"file_descriptor\": %d, \"data\": \"%s\"}\n", fd, buf);
    SSL_write(ssl, jsonStr, strlen(jsonStr));

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = SSL_read(ssl, &response_int, sizeof(response_int));
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);
    }
    return 0;
}

int user_event_delete(const char *path, int operation) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": %d, \"filename\": \"%s\"}\n", operation, path);
    SSL_write(ssl, jsonStr, strlen(jsonStr));

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = SSL_read(ssl, &response_int, sizeof(response_int));
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);
    }
    return 0;
}

int user_event_read(unsigned int fd, const char *buf, size_t count) {
    char jsonStr[1024];
    snprintf(jsonStr, sizeof(jsonStr), "{\"operation\": 4, \"file_descriptor\": %d, \"data\": \"%s\"}\n", fd, buf);
    SSL_write(ssl, jsonStr, strlen(jsonStr));

    int response_int;
    int bytes_received;
    for (int attempts = 0; attempts < 1; ++attempts) {
        bytes_received = SSL_read(ssl, &response_int, sizeof(response_int));
        if (bytes_received > 0) {
            return ntohl(response_int);
        } else if (bytes_received == 0 || errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(100000);
    }
    return 0;
}

static int my_hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result) {
    if (syscall_number == SYS_openat) {
        *result = user_event_open((const char *)arg1, 1);
        return 0;
    } else if (syscall_number == SYS_unlink) {
        *result = user_event_delete((const char *)arg0, 3);
        return 0;
    } else if (syscall_number == SYS_read) {
        char buf_copy[0x1000];
        size_t size = (size_t)arg2;
        if (size > sizeof(buf_copy)) {
            size = sizeof(buf_copy);
        }
        memcpy(buf_copy, (const char *)arg1, size);
        *result = user_event_read((unsigned int)arg0, buf_copy, size);
        return 0;
    }
    return 1;
}

void configure_context(SSL_CTX *ctx) {
    // Load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "/home/atello/.local/share/mkcert/rootCA.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

static void setup_socket() {
    struct sockaddr_in server_addr = {0};

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Socket connect failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(sslctx);
    SSL_set_fd(ssl, socket_fd);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

static __attribute__((constructor)) void init(void) {
    init_openssl();
    sslctx = create_context();
    configure_context(sslctx);
    setup_socket();
    intercept_hook_point = my_hook;
}
