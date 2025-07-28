package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"takakrypt/pkg/netlink"
)

func main() {
	fmt.Println("Testing netlink health check...")

	client, err := netlink.NewClient()
	if err != nil {
		fmt.Printf("Failed to create netlink client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Connect to kernel
	if err := client.Connect(); err != nil {
		fmt.Printf("Failed to connect to kernel: %v\n", err)
		os.Exit(1)
	}

	// Send health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.SendHealthCheck(ctx); err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Netlink health check successful!")
}