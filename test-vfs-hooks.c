#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    const char *path = "/tmp/takakrypt-test/vfs-test.txt";
    const char *data = "Testing VFS hooks\n";
    int fd;
    char buffer[100];
    
    printf("Testing VFS hooks for: %s\n", path);
    
    // Write test
    printf("1. Opening file for write...\n");
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open write");
        return 1;
    }
    
    printf("2. Writing data...\n");
    if (write(fd, data, strlen(data)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    close(fd);
    
    // Read test
    printf("3. Opening file for read...\n");
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open read");
        return 1;
    }
    
    printf("4. Reading data...\n");
    int n = read(fd, buffer, sizeof(buffer)-1);
    if (n < 0) {
        perror("read");
        close(fd);
        return 1;
    }
    buffer[n] = '\0';
    close(fd);
    
    printf("5. Data read: %s", buffer);
    printf("Test complete!\n");
    
    return 0;
}