package agent

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"takakrypt/internal/crypto"
	"takakrypt/internal/policy"
	"takakrypt/internal/process"
	"takakrypt/pkg/netlink"
)

// RequestHandler processes incoming netlink requests
type RequestHandler struct {
	agent           *Agent
	policyEngine    *policy.Engine
	processDetector *process.ProcessDetector
	processEvaluator *process.ProcessSetEvaluator
}

// NewRequestHandler creates a new request handler
func NewRequestHandler(agent *Agent, policyEngine *policy.Engine) *RequestHandler {
	detector := process.NewProcessDetector()
	evaluator := process.NewProcessSetEvaluator(detector)
	
	return &RequestHandler{
		agent:           agent,
		policyEngine:    policyEngine,
		processDetector: detector,
		processEvaluator: evaluator,
	}
}

// ProcessMessage processes a single netlink message
func (h *RequestHandler) ProcessMessage(ctx context.Context, msg *netlink.TakakryptMessage) ([]byte, error) {
	startTime := time.Now()
	
	logrus.WithFields(logrus.Fields{
		"operation": msg.Header.Operation,
		"sequence":  msg.Header.Sequence,
		"data_len":  msg.Header.DataLen,
	}).Info("AGENT_REQUEST: Processing request from kernel")
	
	// Update statistics
	h.agent.stats.mu.Lock()
	h.agent.stats.RequestsProcessed++
	h.agent.stats.LastActivityTime = time.Now()
	h.agent.stats.mu.Unlock()

	var response []byte
	var err error

	switch msg.Header.Operation {
	case netlink.TAKAKRYPT_OP_CHECK_POLICY:
		logrus.Info("AGENT_REQUEST: Handling policy check request")
		response, err = h.handlePolicyCheck(ctx, msg)
		if err == nil {
			logrus.Info("AGENT_REQUEST: Policy check completed successfully")
			h.agent.stats.mu.Lock()
			h.agent.stats.PolicyChecks++
			h.agent.stats.mu.Unlock()
		} else {
			logrus.WithError(err).Error("AGENT_REQUEST: Policy check failed")
		}

	case netlink.TAKAKRYPT_OP_ENCRYPT:
		logrus.Info("AGENT_REQUEST: Handling encryption request")
		response, err = h.handleEncryption(ctx, msg)
		if err == nil {
			logrus.Info("AGENT_REQUEST: Encryption completed successfully")
			h.agent.stats.mu.Lock()
			h.agent.stats.EncryptionOps++
			h.agent.stats.mu.Unlock()
		} else {
			logrus.WithError(err).Error("AGENT_REQUEST: Encryption failed")
		}

	case netlink.TAKAKRYPT_OP_DECRYPT:
		logrus.Info("AGENT_REQUEST: Handling decryption request")
		response, err = h.handleDecryption(ctx, msg)
		if err == nil {
			logrus.Info("AGENT_REQUEST: Decryption completed successfully")
			h.agent.stats.mu.Lock()
			h.agent.stats.DecryptionOps++
			h.agent.stats.mu.Unlock()
		} else {
			logrus.WithError(err).Error("AGENT_REQUEST: Decryption failed")
		}

	case netlink.TAKAKRYPT_OP_HEALTH_CHECK:
		response, err = h.handleHealthCheck(ctx, msg)

	default:
		err = fmt.Errorf("unsupported operation: %d", msg.Header.Operation)
		response, _ = netlink.SerializeResponse(msg.Header.Sequence, msg.Header.Operation, 
			netlink.TAKAKRYPT_STATUS_ERROR, []byte(err.Error()))
	}

	// Update statistics
	duration := time.Since(startTime)
	h.agent.stats.mu.Lock()
	if err != nil {
		h.agent.stats.RequestsFailed++
	} else {
		h.agent.stats.RequestsSuccessful++
	}
	
	// Update average response time
	totalRequests := h.agent.stats.RequestsProcessed
	if totalRequests > 0 {
		h.agent.stats.AverageResponseTime = time.Duration(
			(int64(h.agent.stats.AverageResponseTime)*int64(totalRequests-1) + int64(duration)) / int64(totalRequests))
	}
	h.agent.stats.mu.Unlock()

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"operation": msg.Header.Operation,
			"sequence":  msg.Header.Sequence,
			"duration":  duration,
			"error":     err,
		}).Error("Request processing failed")
	} else {
		logrus.WithFields(logrus.Fields{
			"operation": msg.Header.Operation,
			"sequence":  msg.Header.Sequence,
			"duration":  duration,
		}).Debug("Request processed successfully")
	}

	return response, err
}

// handlePolicyCheck processes policy evaluation requests
func (h *RequestHandler) handlePolicyCheck(ctx context.Context, msg *netlink.TakakryptMessage) ([]byte, error) {
	// Parse the policy check request
	path, operation, uid, gid, pid, err := netlink.ParsePolicyCheckRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy check request: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"path":      path,
		"operation": operation,
		"uid":       uid,
		"gid":       gid,
		"pid":       pid,
	}).Debug("Processing policy check request")

	// Create rule evaluation context
	evalCtx, err := h.createEvaluationContext(path, operation, uid, gid, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to create evaluation context: %w", err)
	}

	// Get the current configuration
	cfg := h.policyEngine.GetConfig()
	if cfg == nil {
		return nil, fmt.Errorf("no policy configuration available")
	}

	// Evaluate the security rules using the policy engine
	result, err := h.policyEngine.EvaluateAccessV2(ctx, evalCtx)
	if err != nil {
		logrus.WithError(err).Warn("Policy evaluation failed, falling back to default")
		// Create a fallback result
		result = &policy.EvaluationResult{
			Allow:   true, // Default allow for fallback
			Encrypt: false,
			Reason:  fmt.Sprintf("Policy evaluation error: %v", err),
		}
	}

	// Determine key ID if encryption is required
	keyID := ""
	if result.Encrypt {
		if result.KeyID != "" {
			keyID = result.KeyID
		} else {
			keyID = fmt.Sprintf("policy-%s-key", cfg.Name)
		}
	}

	// Create and return the response
	response, err := netlink.SerializePolicyCheckResponse(
		msg.Header.Sequence,
		result.Allow,
		result.Encrypt,
		keyID,
		result.Reason,
		cfg.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize policy response: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"path":    path,
		"allowed": result.Allow,
		"encrypt": result.Encrypt,
		"reason":  result.Reason,
		"key_id":  keyID,
	}).Debug("Policy check completed")

	return response, nil
}

// handleEncryption processes encryption requests
func (h *RequestHandler) handleEncryption(ctx context.Context, msg *netlink.TakakryptMessage) ([]byte, error) {
	// Parse the encryption request
	keyID, data, err := netlink.ParseEncryptionRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encryption request: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":    keyID,
		"data_size": len(data),
		"sequence":  msg.Header.Sequence,
	}).Info("AGENT_ENCRYPT: Starting encryption process")

	// Perform encryption using the file encryption engine
	logrus.Info("AGENT_ENCRYPT: Creating file encryption engine")
	fileEngine := crypto.NewFileEncryptionEngine()
	logrus.WithFields(logrus.Fields{
		"key_id": keyID,
		"data_size": len(data),
	}).Info("AGENT_ENCRYPT: Calling encryption engine")
	encryptedData, err := fileEngine.EncryptFile(data, keyID)
	if err != nil {
		logrus.WithError(err).Error("AGENT_ENCRYPT: Encryption engine failed")
		return nil, fmt.Errorf("encryption failed: %w", err)
	}
	logrus.WithFields(logrus.Fields{
		"original_size": len(data),
		"encrypted_size": len(encryptedData),
	}).Info("AGENT_ENCRYPT: Encryption engine succeeded")

	// Create response
	response, err := netlink.SerializeResponse(msg.Header.Sequence, 
		netlink.TAKAKRYPT_OP_ENCRYPT, netlink.TAKAKRYPT_STATUS_SUCCESS, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize encryption response: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":           keyID,
		"plaintext_size":   len(data),
		"ciphertext_size":  len(encryptedData),
		"sequence":        msg.Header.Sequence,
	}).Info("AGENT_ENCRYPT: Encryption operation completed successfully")

	return response, nil
}

// handleDecryption processes decryption requests
func (h *RequestHandler) handleDecryption(ctx context.Context, msg *netlink.TakakryptMessage) ([]byte, error) {
	// Parse the decryption request
	keyID, encryptedData, err := netlink.ParseDecryptionRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decryption request: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":    keyID,
		"data_size": len(encryptedData),
	}).Debug("Processing decryption request")

	// Perform decryption using the file encryption engine
	fileEngine := crypto.NewFileEncryptionEngine()
	decryptedData, err := fileEngine.DecryptFile(encryptedData, keyID)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Create response
	response, err := netlink.SerializeResponse(msg.Header.Sequence, 
		netlink.TAKAKRYPT_OP_DECRYPT, netlink.TAKAKRYPT_STATUS_SUCCESS, decryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decryption response: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":          keyID,
		"ciphertext_size": len(encryptedData),
		"plaintext_size":  len(decryptedData),
	}).Debug("Decryption completed")

	return response, nil
}

// handleHealthCheck processes health check requests
func (h *RequestHandler) handleHealthCheck(ctx context.Context, msg *netlink.TakakryptMessage) ([]byte, error) {
	logrus.Debug("Processing health check request")

	// Simple health check response
	healthData := []byte("OK")
	response, err := netlink.SerializeResponse(msg.Header.Sequence, 
		netlink.TAKAKRYPT_OP_HEALTH_CHECK, netlink.TAKAKRYPT_STATUS_SUCCESS, healthData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize health check response: %w", err)
	}

	logrus.Debug("Health check completed")
	return response, nil
}

// createEvaluationContext creates a policy evaluation context from the request parameters
func (h *RequestHandler) createEvaluationContext(path string, operation, uid, gid, pid uint32) (*policy.EvaluationContext, error) {
	// Map operation number to operation string
	var operationStr string
	switch operation {
	case 1:
		operationStr = "open_read"
	case 2:
		operationStr = "open_write"
	case 3:
		operationStr = "create"
	case 4:
		operationStr = "unlink"
	case 5:
		operationStr = "rename"
	case 6:
		operationStr = "mkdir"
	case 7:
		operationStr = "rmdir"
	case 8:
		operationStr = "readdir"
	case 9:
		operationStr = "getattr"
	case 10:
		operationStr = "setattr"
	default:
		operationStr = "unknown"
	}

	// Get username from UID
	username := ""
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		username = u.Username
	}
	_ = username // Will be used later for logging

	// Get enhanced process information
	processInfo, err := h.processDetector.GetProcessInfo(int(pid))
	if err != nil {
		logrus.WithError(err).Warn("Failed to get process info, using defaults")
		processInfo = &process.ProcessInfo{
			PID:  int(pid),
			Name: "unknown",
			Path: "",
			Type: process.ProcessTypeUnknown,
		}
	}

	// Log database process detection
	if processInfo.Type != process.ProcessTypeUnknown {
		logrus.WithFields(logrus.Fields{
			"pid":           pid,
			"process_name":  processInfo.Name,
			"process_type":  processInfo.Type,
			"database_type": processInfo.DatabaseType,
			"data_paths":    processInfo.DataPaths,
		}).Debug("Enhanced process detection")
	}

	// Get user groups (keep basic implementation for now)
	groups := []string{}
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		if groupIds, err := u.GroupIds(); err == nil {
			for _, gidStr := range groupIds {
				if g, err := user.LookupGroupId(gidStr); err == nil {
					groups = append(groups, g.Name)
				}
			}
		}
	}

	return &policy.EvaluationContext{
		FilePath:    path,
		UserID:      int(uid),
		GroupIDs:    []int{int(gid)}, // TODO: Get all group IDs from groups
		ProcessID:   int(pid),
		ProcessName: processInfo.Name,
		ProcessPath: processInfo.Path,
		Operation:   operationStr,
		Timestamp:   time.Now(),
	}, nil
}// Enhanced logging enabled
