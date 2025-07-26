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
#define TAKAKRYPT_OP_HEALTH_CHECK 6

struct takakrypt_msg_header {
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    uint32_t sequence;
    uint32_t payload_size;
    uint32_t flags;
    uint64_t timestamp;
} __attribute__((packed));

int main() {
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct takakrypt_msg_header *msg;
    struct iovec iov;
    struct msghdr msh;
    int ret;

    printf("Testing netlink communication with Takakrypt kernel module...\n");

    // Create netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, TAKAKRYPT_NETLINK_FAMILY);
    if (sock_fd < 0) {
        printf("Error: Failed to create netlink socket: %s\n", strerror(errno));
        printf("Trying alternative netlink families...\n");
        
        // Try NETLINK_GENERIC
        sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        if (sock_fd < 0) {
            printf("Error: NETLINK_GENERIC also failed: %s\n", strerror(errno));
            return 1;
        } else {
            printf("Warning: Using NETLINK_GENERIC instead of family 31\n");
        }
    } else {
        printf("Success: Netlink socket created with family 31\n");
    }

    // Set up source address
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    // Bind socket
    ret = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (ret < 0) {
        printf("Error: Failed to bind netlink socket: %s\n", strerror(errno));
        close(sock_fd);
        return 1;
    }
    printf("Success: Socket bound to PID %d\n", getpid());

    // Set up destination address (kernel module)
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel

    // Allocate message
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct takakrypt_msg_header)));
    memset(nlh, 0, NLMSG_SPACE(sizeof(struct takakrypt_msg_header)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct takakrypt_msg_header));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // Fill message
    msg = (struct takakrypt_msg_header *)NLMSG_DATA(nlh);
    msg->magic = TAKAKRYPT_MSG_MAGIC;
    msg->version = 1;
    msg->operation = TAKAKRYPT_OP_HEALTH_CHECK;
    msg->sequence = 1;
    msg->payload_size = 0;
    msg->flags = 0;
    msg->timestamp = 0;

    printf("Sending health check message...\n");
    printf("  Magic: 0x%08x\n", msg->magic);
    printf("  Operation: %u (health check)\n", msg->operation);
    printf("  Sequence: %u\n", msg->sequence);

    // Send message
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msh.msg_name = (void *)&dest_addr;
    msh.msg_namelen = sizeof(dest_addr);
    msh.msg_iov = &iov;
    msh.msg_iovlen = 1;
    msh.msg_control = NULL;
    msh.msg_controllen = 0;
    msh.msg_flags = 0;

    ret = sendmsg(sock_fd, &msh, 0);
    if (ret < 0) {
        printf("Error: Failed to send message: %s\n", strerror(errno));
        free(nlh);
        close(sock_fd);
        return 1;
    }
    printf("Success: Message sent (%d bytes)\n", ret);

    printf("Waiting for response...\n");

    // Try to receive response (with timeout)
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(sock_fd, &readfds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    ret = select(sock_fd + 1, &readfds, NULL, NULL, &timeout);
    if (ret > 0) {
        printf("Response received!\n");
        // We could read the response here if needed
    } else if (ret == 0) {
        printf("Timeout: No response received\n");
    } else {
        printf("Error waiting for response: %s\n", strerror(errno));
    }

    free(nlh);
    close(sock_fd);
    printf("Test completed.\n");
    return 0;
}