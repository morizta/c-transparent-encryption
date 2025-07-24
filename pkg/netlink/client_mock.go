// +build !linux

package netlink

import (
	"context"
	"fmt"
	"time"
)

// Client handles communication with the kernel module via netlink (mock for non-Linux)
type Client struct {
	connected bool
}

// Message represents a netlink message (mock)
type Message struct {
	Type      uint32
	Sequence  uint32
	Data      []byte
	Timestamp time.Time
}

// NewClient creates a new netlink client (mock)
func NewClient() (*Client, error) {
	return &Client{connected: false}, nil
}

// Connect establishes connection to the kernel module (mock)
func (c *Client) Connect(ctx context.Context) error {
	c.connected = true
	fmt.Println("[MOCK] Connected to kernel module")
	return nil
}

// Disconnect closes the netlink connection (mock)
func (c *Client) Disconnect() error {
	c.connected = false
	fmt.Println("[MOCK] Disconnected from kernel module")
	return nil
}

// IsConnected returns whether the client is connected (mock)
func (c *Client) IsConnected() bool {
	return c.connected
}

// SendMessage sends a message to the kernel module (mock)
func (c *Client) SendMessage(msg *Message) error {
	if !c.connected {
		return fmt.Errorf("not connected to kernel module")
	}
	fmt.Printf("[MOCK] Sent message: type=%d, seq=%d, data_len=%d\n", msg.Type, msg.Sequence, len(msg.Data))
	return nil
}

// ReceiveMessage receives a message from the kernel module (mock)
func (c *Client) ReceiveMessage(timeout time.Duration) (*Message, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to kernel module")
	}
	
	// Mock response
	msg := &Message{
		Type:      1,
		Sequence:  1,
		Data:      []byte("mock response"),
		Timestamp: time.Now(),
	}
	
	fmt.Printf("[MOCK] Received message: type=%d, seq=%d\n", msg.Type, msg.Sequence)
	return msg, nil
}

// SendPolicyCheckRequest sends a policy check request (mock)
func (c *Client) SendPolicyCheckRequest(filepath string, uid, pid uint32, operation uint32) (*Message, error) {
	fmt.Printf("[MOCK] Policy check: %s (uid=%d, pid=%d, op=%d)\n", filepath, uid, pid, operation)
	return &Message{
		Type:      1,
		Sequence:  1,
		Data:      []byte("allowed"),
		Timestamp: time.Now(),
	}, nil
}

// SendEncryptionRequest sends an encryption request (mock)
func (c *Client) SendEncryptionRequest(keyID string, data []byte) (*Message, error) {
	fmt.Printf("[MOCK] Encrypt request: keyID=%s, size=%d\n", keyID, len(data))
	return &Message{
		Type:      2,
		Sequence:  2,
		Data:      []byte("encrypted_data"),
		Timestamp: time.Now(),
	}, nil
}

// SendDecryptionRequest sends a decryption request (mock)
func (c *Client) SendDecryptionRequest(keyID string, encryptedData []byte) (*Message, error) {
	fmt.Printf("[MOCK] Decrypt request: keyID=%s, size=%d\n", keyID, len(encryptedData))
	return &Message{
		Type:      3,
		Sequence:  3,
		Data:      []byte("decrypted_data"),
		Timestamp: time.Now(),
	}, nil
}

// SendStatusRequest sends a status request (mock)
func (c *Client) SendStatusRequest() (*Message, error) {
	fmt.Println("[MOCK] Status request")
	return &Message{
		Type:      4,
		Sequence:  4,
		Data:      []byte("status_ok"),
		Timestamp: time.Now(),
	}, nil
}