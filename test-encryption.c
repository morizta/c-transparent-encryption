#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <stdint.h>
#include <sys/select.h>

#define TAKAKRYPT_NETLINK_FAMILY 31
#define TAKAKRYPT_MSG_MAGIC 0x54414B41
#define TAKAKRYPT_OP_ENCRYPT 2
#define TAKAKRYPT_OP_DECRYPT 3

struct takakrypt_msg_header {
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    uint32_t sequence;
    uint32_t payload_size;
    uint32_t flags;
    uint64_t timestamp;
} __attribute__((packed));

struct takakrypt_crypto_request {
    struct takakrypt_msg_header header;
    uint32_t request_id;
    char key_id[64];
    uint32_t data_length;
    uint8_t data[];
} __attribute__((packed));

int test_encryption() {
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct takakrypt_crypto_request *req;
    char test_data[] = "Hello, transparent encryption!";
    int data_len = strlen(test_data);
    int total_size = sizeof(struct takakrypt_crypto_request) + data_len;
    
    printf("Testing encryption request...\n");
    printf("Data to encrypt: '%s' (%d bytes)\n", test_data, data_len);

    // Create netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, TAKAKRYPT_NETLINK_FAMILY);
    if (sock_fd < 0) {
        printf("Error: Failed to create netlink socket: %s\n", strerror(errno));
        return 1;
    }

    // Set up addresses
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        printf("Error: Failed to bind socket: %s\n", strerror(errno));
        close(sock_fd);
        return 1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel

    // Allocate message
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(total_size));
    memset(nlh, 0, NLMSG_SPACE(total_size));
    nlh->nlmsg_len = NLMSG_SPACE(total_size);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // Fill encryption request
    req = (struct takakrypt_crypto_request *)NLMSG_DATA(nlh);
    req->header.magic = TAKAKRYPT_MSG_MAGIC;
    req->header.version = 1;
    req->header.operation = TAKAKRYPT_OP_ENCRYPT;
    req->header.sequence = 42;
    req->header.payload_size = total_size - sizeof(struct takakrypt_msg_header);
    req->header.flags = 0;
    req->header.timestamp = 0;
    
    req->request_id = 12345;
    strncpy(req->key_id, "test-key-123", sizeof(req->key_id) - 1);
    req->data_length = data_len;
    memcpy(req->data, test_data, data_len);

    printf("Sending encryption request:\n");
    printf("  Operation: %u (encrypt)\n", req->header.operation);
    printf("  Key ID: %s\n", req->key_id);
    printf("  Data length: %u\n", req->data_length);

    // Send message
    struct iovec iov = {nlh, nlh->nlmsg_len};
    struct msghdr msh = {
        .msg_name = &dest_addr,
        .msg_namelen = sizeof(dest_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    int ret = sendmsg(sock_fd, &msh, 0);
    if (ret < 0) {
        printf("Error: Failed to send message: %s\n", strerror(errno));
        free(nlh);
        close(sock_fd);
        return 1;
    }
    printf("Success: Encryption request sent (%d bytes)\n", ret);

    // Wait for response
    printf("Waiting for encrypted response...\n");
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(sock_fd, &readfds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    ret = select(sock_fd + 1, &readfds, NULL, NULL, &timeout);
    if (ret > 0) {
        printf("Response received! (Encryption would be processed by kernel module)\n");
    } else if (ret == 0) {
        printf("Timeout: No response received\n");
    } else {
        printf("Error waiting for response: %s\n", strerror(errno));
    }

    free(nlh);
    close(sock_fd);
    return 0;
}

int main() {
    printf("=== Takakrypt Encryption Test ===\n");
    test_encryption();
    printf("Test completed.\n");
    return 0;
}