#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static bool tor_is_pid_one(void)
{
    char command[32] = {0};
    int fd = open("/proc/1/comm", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    ssize_t count = read(fd, command, sizeof(command) - 1);
    close(fd);
    if (count <= 0) {
        return false;
    }
    command[count] = '\0';
    return strncmp(command, "tor\n", 4) == 0 || strncmp(command, "tor", 3) == 0;
}

static bool read_exact(int fd, unsigned char *buffer, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = recv(fd, buffer + offset, length - offset, 0);
        if (count <= 0) {
            return false;
        }
        offset += (size_t)count;
    }
    return true;
}

int main(void)
{
    if (!tor_is_pid_one()) {
        return EXIT_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return EXIT_FAILURE;
    }

    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(9050),
    };
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    const unsigned char greeting[] = {0x05, 0x01, 0x00};
    unsigned char response[2] = {0};
    bool valid = send(fd, greeting, sizeof(greeting), 0) == (ssize_t)sizeof(greeting) &&
                 read_exact(fd, response, sizeof(response)) && response[0] == 0x05 &&
                 response[1] == 0x00;
    close(fd);
    return valid ? EXIT_SUCCESS : EXIT_FAILURE;
}
