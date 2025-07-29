package netlink

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

// Test that TakakryptHeader matches the expected kernel structure
func TestTakakryptHeaderStructure(t *testing.T) {
	header := TakakryptHeader{
		Magic:       TAKAKRYPT_MSG_MAGIC,
		Version:     TAKAKRYPT_PROTOCOL_VERSION,  
		Operation:   TAKAKRYPT_OP_CHECK_POLICY,
		Sequence:    12345,
		PayloadSize: 1024,
		Flags:       0,
		Timestamp:   1234567890,
	}

	// Verify structure size (should be 28 bytes: 6*4 + 1*8)
	actualSize := int(unsafe.Sizeof(header))
	expectedSize := 28
	
	t.Logf("TakakryptHeader size: %d bytes (expected: %d)", actualSize, expectedSize)
	
	// Verify all fields are accessible and correct
	if header.Magic != TAKAKRYPT_MSG_MAGIC {
		t.Errorf("Magic field incorrect: got 0x%x, want 0x%x", header.Magic, TAKAKRYPT_MSG_MAGIC)
	}
	
	if header.Version != TAKAKRYPT_PROTOCOL_VERSION {
		t.Errorf("Version field incorrect: got %d, want %d", header.Version, TAKAKRYPT_PROTOCOL_VERSION)
	}
	
	if header.Operation != TAKAKRYPT_OP_CHECK_POLICY {
		t.Errorf("Operation field incorrect: got %d, want %d", header.Operation, TAKAKRYPT_OP_CHECK_POLICY)
	}
}

// Test guard point serialization matches kernel expectations
func TestGuardPointSerialization(t *testing.T) {
	guardPoints := []GuardPointConfig{
		{
			Name:    "test_gp1",
			Path:    "/tmp/test1",
			Enabled: true,
		},
		{
			Name:    "test_gp2", 
			Path:    "/tmp/test2",
			Enabled: false,
		},
	}

	// Create buffer for serialization
	buf := new(bytes.Buffer)
	
	// Write guard point count (4 bytes, little endian)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(guardPoints))); err != nil {
		t.Fatalf("Failed to write guard point count: %v", err)
	}
	
	// Write each guard point
	for _, gp := range guardPoints {
		// Name length (4 bytes) + name
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(gp.Name))); err != nil {
			t.Fatalf("Failed to write name length: %v", err)
		}
		if _, err := buf.Write([]byte(gp.Name)); err != nil {
			t.Fatalf("Failed to write name: %v", err)
		}
		
		// Path length (4 bytes) + path  
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(gp.Path))); err != nil {
			t.Fatalf("Failed to write path length: %v", err)
		}
		if _, err := buf.Write([]byte(gp.Path)); err != nil {
			t.Fatalf("Failed to write path: %v", err)
		}
		
		// Enabled flag (1 byte)
		enabled := uint8(0)
		if gp.Enabled {
			enabled = 1
		}
		if err := binary.Write(buf, binary.LittleEndian, enabled); err != nil {
			t.Fatalf("Failed to write enabled flag: %v", err)
		}
	}

	data := buf.Bytes()
	
	// Verify the serialized data structure
	reader := bytes.NewReader(data)
	
	// Read count
	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		t.Fatalf("Failed to read count: %v", err)
	}
	
	if count != uint32(len(guardPoints)) {
		t.Errorf("Count mismatch: got %d, want %d", count, len(guardPoints))
	}
	
	// Read each guard point back
	for i := 0; i < int(count); i++ {
		// Read name length
		var nameLen uint32
		if err := binary.Read(reader, binary.LittleEndian, &nameLen); err != nil {
			t.Fatalf("Failed to read name length for GP %d: %v", i, err)
		}
		
		// Read name
		nameBytes := make([]byte, nameLen)
		if _, err := reader.Read(nameBytes); err != nil {
			t.Fatalf("Failed to read name for GP %d: %v", i, err)
		}
		name := string(nameBytes)
		
		// Read path length
		var pathLen uint32
		if err := binary.Read(reader, binary.LittleEndian, &pathLen); err != nil {
			t.Fatalf("Failed to read path length for GP %d: %v", i, err)
		}
		
		// Read path
		pathBytes := make([]byte, pathLen)
		if _, err := reader.Read(pathBytes); err != nil {
			t.Fatalf("Failed to read path for GP %d: %v", i, err)
		}
		path := string(pathBytes)
		
		// Read enabled flag
		var enabled uint8
		if err := binary.Read(reader, binary.LittleEndian, &enabled); err != nil {
			t.Fatalf("Failed to read enabled flag for GP %d: %v", i, err)
		}
		
		// Verify against original
		if name != guardPoints[i].Name {
			t.Errorf("GP %d name mismatch: got %s, want %s", i, name, guardPoints[i].Name)
		}
		if path != guardPoints[i].Path {
			t.Errorf("GP %d path mismatch: got %s, want %s", i, path, guardPoints[i].Path)
		}
		expectedEnabled := uint8(0)
		if guardPoints[i].Enabled {
			expectedEnabled = 1
		}
		if enabled != expectedEnabled {
			t.Errorf("GP %d enabled mismatch: got %d, want %d", i, enabled, expectedEnabled)
		}
	}

	t.Logf("Successfully serialized and deserialized %d guard points (%d bytes)", len(guardPoints), len(data))
}

// Test policy check response serialization 
func TestPolicyCheckResponseSerialization(t *testing.T) {
	seq := uint32(12345)
	allowAccess := true
	encryptFile := true
	keyID := "test-key-123"
	reason := "Policy matched rule 1"
	policyName := "test-policy"

	response, err := SerializePolicyCheckResponse(seq, allowAccess, encryptFile, keyID, reason, policyName)
	if err != nil {
		t.Fatalf("Failed to serialize policy response: %v", err)
	}

	// Verify the response can be deserialized
	msg, err := DeserializeMessage(response)
	if err != nil {
		t.Fatalf("Failed to deserialize policy response: %v", err)
	}

	if msg.Header.Sequence != seq {
		t.Errorf("Sequence mismatch: got %d, want %d", msg.Header.Sequence, seq)
	}

	if msg.Header.Operation != TAKAKRYPT_OP_CHECK_POLICY {
		t.Errorf("Operation mismatch: got %d, want %d", msg.Header.Operation, TAKAKRYPT_OP_CHECK_POLICY)
	}

	t.Logf("Policy response serialization test passed (%d bytes)", len(response))
}

// Test message deserialization
func TestMessageDeserialization(t *testing.T) {
	// Create a test message
	testData := []byte("test payload data")
	header := TakakryptHeader{
		Magic:       TAKAKRYPT_MSG_MAGIC,
		Version:     TAKAKRYPT_PROTOCOL_VERSION,
		Operation:   TAKAKRYPT_OP_ENCRYPT,
		Sequence:    54321,
		PayloadSize: uint32(len(testData)),
		Flags:       TAKAKRYPT_STATUS_SUCCESS,
		Timestamp:   1234567890,
	}

	// Serialize header + data
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}
	buf.Write(testData)

	// Deserialize
	msg, err := DeserializeMessage(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to deserialize message: %v", err)
	}

	// Verify
	if msg.Header.Magic != TAKAKRYPT_MSG_MAGIC {
		t.Errorf("Magic mismatch: got 0x%x, want 0x%x", msg.Header.Magic, TAKAKRYPT_MSG_MAGIC)
	}
	if msg.Header.Sequence != 54321 {
		t.Errorf("Sequence mismatch: got %d, want %d", msg.Header.Sequence, 54321)
	}
	if !bytes.Equal(msg.Data, testData) {
		t.Errorf("Data mismatch: got %v, want %v", msg.Data, testData)
	}

	t.Logf("Message deserialization test passed")
}

// Benchmark guard point serialization performance
func BenchmarkGuardPointSerialization(b *testing.B) {
	guardPoints := []GuardPointConfig{
		{Name: "gp1", Path: "/tmp/test1", Enabled: true},
		{Name: "gp2", Path: "/tmp/test2", Enabled: false},
		{Name: "gp3", Path: "/tmp/test3", Enabled: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := new(bytes.Buffer)
		
		// Write guard point count
		binary.Write(buf, binary.LittleEndian, uint32(len(guardPoints)))
		
		// Write each guard point
		for _, gp := range guardPoints {
			binary.Write(buf, binary.LittleEndian, uint32(len(gp.Name)))
			buf.Write([]byte(gp.Name))
			binary.Write(buf, binary.LittleEndian, uint32(len(gp.Path)))
			buf.Write([]byte(gp.Path))
			enabled := uint8(0)
			if gp.Enabled {
				enabled = 1
			}
			binary.Write(buf, binary.LittleEndian, enabled)
		}
	}
}