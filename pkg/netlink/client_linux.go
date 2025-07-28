// +build linux

package netlink

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// Client handles communication with the kernel module via netlink
type Client struct {
	fd         int
	addr       *syscall.SockaddrNetlink
	connected  bool
	mu         sync.RWMutex
	sequenceID uint32
}

// Message represents a netlink message
type Message struct {
	Type      uint32
	Sequence  uint32
	Data      []byte
	Timestamp time.Time
}

// Constants for netlink communication
const (
	TAKAKRYPT_NETLINK_FAMILY = 31

	// Additional status codes (others are in protocol.go)
	TAKAKRYPT_STATUS_NOT_FOUND      = 3
	TAKAKRYPT_STATUS_INVALID_REQUEST = 4
	TAKAKRYPT_STATUS_TIMEOUT        = 5
	TAKAKRYPT_STATUS_NO_AGENT       = 6

	// Maximum message size
	TAKAKRYPT_MAX_MSG_SIZE = 65536
)

// MessageHeader represents the message header structure
type MessageHeader struct {
	Magic       uint32
	Version     uint32
	Operation   uint32
	Sequence    uint32
	PayloadSize uint32
	Flags       uint32
	Timestamp   uint64
}

// NewClient creates a new netlink client
func NewClient() (*Client, error) {
	client := &Client{
		fd:        -1,
		connected: false,
	}

	return client, nil
}

// Connect establishes connection to the kernel module
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	logrus.Info("Connecting to kernel module via netlink")

	// Create netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, TAKAKRYPT_NETLINK_FAMILY)
	if err != nil {
		return fmt.Errorf("failed to create netlink socket: %w", err)
	}

	// Bind socket
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(syscall.Getpid()),
		Groups: 0,
	}

	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("failed to bind netlink socket: %w", err)
	}

	c.fd = fd
	c.addr = addr
	c.connected = true

	logrus.WithFields(logrus.Fields{
		"fd":      c.fd,
		"pid":     addr.Pid,
		"family":  TAKAKRYPT_NETLINK_FAMILY,
	}).Info("Connected to kernel module")

	// Unlock mutex before sending health check to avoid deadlock
	c.mu.Unlock()
	
	// Send initial health check to announce our presence
	logrus.Info("Sending initial health check to kernel")
	if err := c.sendHealthCheck(); err != nil {
		logrus.WithError(err).Error("Failed to send initial health check")
		// Reacquire lock before returning
		c.mu.Lock()
		return fmt.Errorf("failed to send initial health check: %w", err)
	}
	logrus.Info("Initial health check sent successfully")
	
	// Reacquire lock before returning
	c.mu.Lock()

	logrus.WithFields(logrus.Fields{
		"fd":      c.fd,
		"pid":     addr.Pid,
		"family":  TAKAKRYPT_NETLINK_FAMILY,
	}).Info("Connected to kernel module")

	return nil
}

// Disconnect closes the netlink connection
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	logrus.Info("Disconnecting from kernel module")

	if c.fd >= 0 {
		if err := syscall.Close(c.fd); err != nil {
			logrus.WithError(err).Warn("Error closing netlink socket")
		}
		c.fd = -1
	}

	c.connected = false
	c.addr = nil

	logrus.Info("Disconnected from kernel module")
	return nil
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// SendMessage sends a message to the kernel module
func (c *Client) SendMessage(msg *Message) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return fmt.Errorf("not connected to kernel module")
	}

	logrus.WithFields(logrus.Fields{
		"operation": msg.Type,
		"sequence":  msg.Sequence,
		"data_len":  len(msg.Data),
	}).Debug("Preparing to send message to kernel")

	// Create message header
	header := MessageHeader{
		Magic:       TAKAKRYPT_MSG_MAGIC,
		Version:     TAKAKRYPT_PROTOCOL_VERSION,
		Operation:   msg.Type,
		Sequence:    msg.Sequence,
		PayloadSize: uint32(len(msg.Data)),
		Flags:       0,
		Timestamp:   uint64(time.Now().Unix()),
	}

	// Serialize header and payload
	headerBytes := (*[unsafe.Sizeof(header)]byte)(unsafe.Pointer(&header))[:]
	totalSize := len(headerBytes) + len(msg.Data)

	if totalSize > TAKAKRYPT_MAX_MSG_SIZE {
		return fmt.Errorf("message too large: %d bytes (max %d)", totalSize, TAKAKRYPT_MAX_MSG_SIZE)
	}

	// Create netlink message
	nlmsg := make([]byte, syscall.NLMSG_HDRLEN+totalSize)
	
	// Netlink header
	nlmsgHdr := (*syscall.NlMsghdr)(unsafe.Pointer(&nlmsg[0]))
	nlmsgHdr.Len = uint32(len(nlmsg))
	nlmsgHdr.Type = syscall.NLMSG_DONE
	nlmsgHdr.Flags = 0
	nlmsgHdr.Seq = msg.Sequence
	nlmsgHdr.Pid = c.addr.Pid

	// Copy our header and payload
	copy(nlmsg[syscall.NLMSG_HDRLEN:], headerBytes)
	if len(msg.Data) > 0 {
		copy(nlmsg[syscall.NLMSG_HDRLEN+len(headerBytes):], msg.Data)
	}

	// Send message
	dest := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0, // Kernel
		Groups: 0,
	}

	logrus.WithFields(logrus.Fields{
		"fd":        c.fd,
		"dest_pid":  dest.Pid,
		"msg_len":   len(nlmsg),
		"total_size": totalSize,
	}).Debug("About to send netlink message")

	if err := syscall.Sendto(c.fd, nlmsg, 0, dest); err != nil {
		logrus.WithError(err).Error("syscall.Sendto failed")
		return fmt.Errorf("failed to send netlink message: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"operation": msg.Type,
		"sequence":  msg.Sequence,
		"size":      totalSize,
	}).Info("Successfully sent message to kernel")

	return nil
}

// ReceiveMessage receives a message from the kernel module
func (c *Client) ReceiveMessage(timeout time.Duration) (*Message, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected to kernel module")
	}

	// Set receive timeout
	if timeout > 0 {
		tv := syscall.Timeval{
			Sec:  int64(timeout.Seconds()),
			Usec: int64(timeout.Nanoseconds()/1000) % 1000000,
		}
		if err := syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, fmt.Errorf("failed to set receive timeout: %w", err)
		}
	}

	// Receive message
	buf := make([]byte, TAKAKRYPT_MAX_MSG_SIZE)
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to receive netlink message: %w", err)
	}

	if n < syscall.NLMSG_HDRLEN {
		return nil, fmt.Errorf("message too short: %d bytes", n)
	}

	// Parse netlink header
	nlmsgHdr := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if int(nlmsgHdr.Len) > n {
		return nil, fmt.Errorf("invalid message length: header says %d, received %d", nlmsgHdr.Len, n)
	}

	// Extract payload
	payloadStart := syscall.NLMSG_HDRLEN
	payloadLen := int(nlmsgHdr.Len) - syscall.NLMSG_HDRLEN

	if payloadLen < int(unsafe.Sizeof(MessageHeader{})) {
		return nil, fmt.Errorf("payload too short for message header")
	}

	// Parse our message header
	header := (*MessageHeader)(unsafe.Pointer(&buf[payloadStart]))
	
	// Validate header
	if header.Magic != TAKAKRYPT_MSG_MAGIC {
		return nil, fmt.Errorf("invalid message magic: 0x%08x", header.Magic)
	}

	if header.Version != TAKAKRYPT_PROTOCOL_VERSION {
		return nil, fmt.Errorf("unsupported protocol version: %d", header.Version)
	}

	// Extract data payload
	var data []byte
	if header.PayloadSize > 0 {
		dataStart := payloadStart + int(unsafe.Sizeof(MessageHeader{}))
		if dataStart+int(header.PayloadSize) > n {
			return nil, fmt.Errorf("invalid payload size: %d", header.PayloadSize)
		}
		data = make([]byte, header.PayloadSize)
		copy(data, buf[dataStart:dataStart+int(header.PayloadSize)])
	}

	msg := &Message{
		Type:      header.Operation,
		Sequence:  header.Sequence,
		Data:      data,
		Timestamp: time.Unix(int64(header.Timestamp), 0),
	}

	logrus.WithFields(logrus.Fields{
		"operation": msg.Type,
		"sequence":  msg.Sequence,
		"size":      len(data),
	}).Debug("Received message from kernel")

	return msg, nil
}

// getNextSequence returns the next sequence number
func (c *Client) getNextSequence() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequenceID++
	logrus.WithField("sequence", c.sequenceID).Debug("Generated sequence number")
	return c.sequenceID
}

// sendHealthCheck sends a health check message to the kernel
func (c *Client) sendHealthCheck() error {
	logrus.Debug("Creating health check message")
	msg := &Message{
		Type:      TAKAKRYPT_OP_HEALTH_CHECK,
		Sequence:  c.getNextSequence(),
		Data:      nil,
		Timestamp: time.Now(),
	}

	logrus.WithFields(logrus.Fields{
		"type":     msg.Type,
		"sequence": msg.Sequence,
	}).Debug("Sending health check message")

	err := c.SendMessage(msg)
	if err != nil {
		logrus.WithError(err).Error("Failed to send health check message")
		return err
	}

	logrus.Debug("Health check message sent successfully")
	return nil
}

// SendPolicyCheckRequest sends a policy check request
func (c *Client) SendPolicyCheckRequest(filepath string, uid, pid uint32, operation uint32) (*Message, error) {
	// TODO: Implement policy check request serialization
	logrus.WithFields(logrus.Fields{
		"filepath":  filepath,
		"uid":       uid,
		"pid":       pid,
		"operation": operation,
	}).Debug("Sending policy check request")

	msg := &Message{
		Type:      TAKAKRYPT_OP_CHECK_POLICY,
		Sequence:  c.getNextSequence(),
		Data:      []byte(fmt.Sprintf("policy_check:%s:%d:%d:%d", filepath, uid, pid, operation)),
		Timestamp: time.Now(),
	}

	if err := c.SendMessage(msg); err != nil {
		return nil, err
	}

	// Wait for response
	response, err := c.ReceiveMessage(5 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to receive policy response: %w", err)
	}

	if response.Sequence != msg.Sequence {
		return nil, fmt.Errorf("sequence mismatch: sent %d, received %d", msg.Sequence, response.Sequence)
	}

	return response, nil
}

// SendEncryptionRequest sends an encryption request
func (c *Client) SendEncryptionRequest(keyID string, data []byte) (*Message, error) {
	logrus.WithFields(logrus.Fields{
		"key_id":    keyID,
		"data_size": len(data),
	}).Debug("Sending encryption request")

	seq := c.getNextSequence()

	// Serialize encryption request using proper protocol
	requestData, err := SerializeEncryptionRequest(seq, keyID, data)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize encryption request: %w", err)
	}

	msg := &Message{
		Type:      TAKAKRYPT_OP_ENCRYPT,
		Sequence:  seq,
		Data:      requestData,
		Timestamp: time.Now(),
	}

	if err := c.SendMessage(msg); err != nil {
		return nil, err
	}

	// Wait for response
	response, err := c.ReceiveMessage(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to receive encryption response: %w", err)
	}

	if response.Sequence != msg.Sequence {
		return nil, fmt.Errorf("sequence mismatch: sent %d, received %d", msg.Sequence, response.Sequence)
	}

	return response, nil
}

// SendDecryptionRequest sends a decryption request
func (c *Client) SendDecryptionRequest(keyID string, encryptedData []byte) (*Message, error) {
	logrus.WithFields(logrus.Fields{
		"key_id":    keyID,
		"data_size": len(encryptedData),
	}).Debug("Sending decryption request")

	seq := c.getNextSequence()

	// Serialize decryption request using proper protocol
	requestData, err := SerializeDecryptionRequest(seq, keyID, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decryption request: %w", err)
	}

	msg := &Message{
		Type:      TAKAKRYPT_OP_DECRYPT,
		Sequence:  seq,
		Data:      requestData,
		Timestamp: time.Now(),
	}

	if err := c.SendMessage(msg); err != nil {
		return nil, err
	}

	// Wait for response
	response, err := c.ReceiveMessage(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to receive decryption response: %w", err)
	}

	if response.Sequence != msg.Sequence {
		return nil, fmt.Errorf("sequence mismatch: sent %d, received %d", msg.Sequence, response.Sequence)
	}

	return response, nil
}

// SendStatusRequest sends a status request to get kernel module statistics
func (c *Client) SendStatusRequest() (*Message, error) {
	logrus.Debug("Sending status request")

	msg := &Message{
		Type:      TAKAKRYPT_OP_GET_STATUS,
		Sequence:  c.getNextSequence(),
		Data:      nil,
		Timestamp: time.Now(),
	}

	if err := c.SendMessage(msg); err != nil {
		return nil, err
	}

	// Wait for response
	response, err := c.ReceiveMessage(5 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to receive status response: %w", err)
	}

	if response.Sequence != msg.Sequence {
		return nil, fmt.Errorf("sequence mismatch: sent %d, received %d", msg.Sequence, response.Sequence)
	}

	return response, nil
}

// GuardPointConfig represents guard point configuration for kernel
type GuardPointConfig struct {
	Name     string
	Path     string
	Enabled  bool
}

// ConfigUpdateData represents configuration data to send to kernel
type ConfigUpdateData struct {
	GuardPoints []GuardPointConfig
}

// SendConfigUpdate sends guard point configuration to kernel module
func (c *Client) SendConfigUpdate(guardPoints []GuardPointConfig) error {
	logrus.WithField("guard_points", len(guardPoints)).Debug("Sending configuration update to kernel")
	
	// Serialize guard points to send to kernel
	// For now, send a simple format: count + (name_len + name + path_len + path + enabled) for each
	var data []byte
	
	// Add guard point count (4 bytes)
	count := make([]byte, 4)
	for i := 0; i < 4; i++ {
		count[i] = byte(len(guardPoints) >> (8 * (3 - i)))
	}
	data = append(data, count...)
	
	// Add each guard point
	for _, gp := range guardPoints {
		// Name length (4 bytes) + name
		nameLen := make([]byte, 4)
		for i := 0; i < 4; i++ {
			nameLen[i] = byte(len(gp.Name) >> (8 * (3 - i)))
		}
		data = append(data, nameLen...)
		data = append(data, []byte(gp.Name)...)
		
		// Path length (4 bytes) + path  
		pathLen := make([]byte, 4)
		for i := 0; i < 4; i++ {
			pathLen[i] = byte(len(gp.Path) >> (8 * (3 - i)))
		}
		data = append(data, pathLen...)
		data = append(data, []byte(gp.Path)...)
		
		// Enabled flag (1 byte)
		if gp.Enabled {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}
	
	msg := &Message{
		Type:      TAKAKRYPT_OP_SET_CONFIG,
		Sequence:  c.getNextSequence(),
		Data:      data,
		Timestamp: time.Now(),
	}
	
	if err := c.SendMessage(msg); err != nil {
		return fmt.Errorf("failed to send config update: %w", err)
	}
	
	logrus.Info("Configuration sent to kernel module successfully")
	return nil
}

// Enhanced logging enabled
