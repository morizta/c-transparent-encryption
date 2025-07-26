#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>

int main() {
    printf("=== Testing UID Detection by Kernel Module ===\n");
    
    // Show current process info
    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t pid = getpid();
    
    struct passwd *pw = getpwuid(uid);
    char *username = pw ? pw->pw_name : "unknown";
    
    printf("Current process info:\n");
    printf("  UID: %u (%s)\n", uid, username);
    printf("  GID: %u\n", gid);
    printf("  PID: %u\n", pid);
    printf("\n");
    
    // Test file creation that should be intercepted
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/takakrypt-test/uid-test-%u.txt", uid);
    
    printf("Creating test file: %s\n", filename);
    printf("This should be intercepted by takakrypt VFS hooks.\n");
    printf("Check /proc/takakrypt/status for statistics.\n\n");
    
    // Create and write to file
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        char data[256];
        snprintf(data, sizeof(data), "Test data from UID %u (%s)\nPID: %u\nGID: %u\n", 
                 uid, username, pid, gid);
        
        write(fd, data, strlen(data));
        close(fd);
        printf("✓ File created successfully\n");
        
        // Read it back
        fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            char buffer[512];
            int bytes = read(fd, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("✓ File read successfully:\n%s\n", buffer);
            }
            close(fd);
        }
    } else {
        perror("Failed to create file");
        return 1;
    }
    
    printf("Test completed. Check kernel module statistics.\n");
    return 0;
}