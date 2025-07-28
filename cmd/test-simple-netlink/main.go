package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	TAKAKRYPT_NETLINK_FAMILY = 31
	TAKAKRYPT_MAGIC          = 0x54414B41 // "TAKA"
)

func main() {
	fmt.Println("Testing basic netlink socket connection...")

	// Create netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, TAKAKRYPT_NETLINK_FAMILY)
	if err != nil {
		fmt.Printf("Failed to create netlink socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	// Bind socket
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
	}

	if err := syscall.Bind(fd, addr); err != nil {
		fmt.Printf("Failed to bind netlink socket: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Netlink socket created and bound successfully!")
	fmt.Printf("Socket FD: %d\n", fd)
	fmt.Printf("PID: %d\n", os.Getpid())
	fmt.Printf("Netlink family: %d\n", TAKAKRYPT_NETLINK_FAMILY)

}