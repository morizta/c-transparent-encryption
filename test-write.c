#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    const char *filepath = "/tmp/takakrypt-test/write-test.txt";
    const char *content = "This should be encrypted when written!";
    
    printf("Opening file: %s\n", filepath);
    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    printf("Writing content: %s\n", content);
    ssize_t written = write(fd, content, strlen(content));
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    
    printf("Written %ld bytes\n", written);
    close(fd);
    
    // Now try to read it back
    printf("\nReading file back...\n");
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open for read");
        return 1;
    }
    
    char buffer[1024];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("read");
        close(fd);
        return 1;
    }
    
    buffer[bytes_read] = '\0';
    printf("Read %ld bytes: %s\n", bytes_read, buffer);
    close(fd);
    
    return 0;
}