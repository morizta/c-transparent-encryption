# Takakrypt Technical Implementation Guide

## Overview

This document provides comprehensive technical implementation details for the Takakrypt transparent encryption system, covering kernel module implementation, userspace agent architecture, communication protocols, and integration patterns.

## Table of Contents

1. [Kernel Module Implementation](#kernel-module-implementation)
2. [Userspace Agent Implementation](#userspace-agent-implementation)
3. [Communication Protocols](#communication-protocols)
4. [Data Structures and Algorithms](#data-structures-and-algorithms)
5. [Security Implementation](#security-implementation)
6. [Performance Optimization](#performance-optimization)
7. [Error Handling and Recovery](#error-handling-and-recovery)
8. [Testing and Validation](#testing-and-validation)
9. [Deployment and Configuration](#deployment-and-configuration)
10. [Troubleshooting Guide](#troubleshooting-guide)

---

## Kernel Module Implementation

### Module Structure

The Takakrypt kernel implementation consists of two primary modules:

#### 1. takakrypt.ko - Core Module

**Purpose**: Primary kernel component handling VFS interception and policy enforcement

**Key Files and Functions**:

```c
// main.c - Module initialization and lifecycle
static int __init takakrypt_init_module(void)
{
    int ret;
    
    // Initialize global state
    takakrypt_global_state = kzalloc(sizeof(struct takakrypt_state), GFP_KERNEL);
    if (!takakrypt_global_state) {
        return -ENOMEM;
    }
    
    // Initialize subsystems
    ret = takakrypt_cache_init();
    if (ret) goto cleanup_state;
    
    ret = takakrypt_netlink_init();
    if (ret) goto cleanup_cache;
    
    ret = takakrypt_vfs_hooks_init();
    if (ret) goto cleanup_netlink;
    
    ret = takakrypt_kprobe_hooks_init();
    if (ret) goto cleanup_vfs;
    
    ret = takakrypt_proc_init();
    if (ret) goto cleanup_kprobe;
    
    takakrypt_info("Takakrypt module loaded successfully\n");
    return 0;
    
cleanup_kprobe:
    takakrypt_kprobe_hooks_cleanup();
cleanup_vfs:
    takakrypt_vfs_hooks_cleanup();
cleanup_netlink:
    takakrypt_netlink_cleanup();
cleanup_cache:
    takakrypt_cache_cleanup();
cleanup_state:
    kfree(takakrypt_global_state);
    return ret;
}
```

**VFS Hook Implementation**:

```c
// vfs_hooks.c - Virtual File System interception
static int takakrypt_file_open(struct inode *inode, struct file *file)
{
    struct takakrypt_file_context *ctx;
    char *filepath;
    int ret;
    
    // Get full file path
    filepath = takakrypt_get_file_path(file);
    if (IS_ERR(filepath)) {
        return PTR_ERR(filepath);
    }
    
    // Check if file is in a guard point
    if (!takakrypt_should_intercept(filepath, current)) {
        kfree(filepath);
        return 0;
    }
    
    // Create file context
    ctx = takakrypt_create_file_context(file, filepath);
    if (IS_ERR(ctx)) {
        kfree(filepath);
        return PTR_ERR(ctx);
    }
    
    // Store context in file private data
    file->private_data = ctx;
    
    takakrypt_debug("File opened: %s (context: %p)\n", filepath, ctx);
    kfree(filepath);
    return 0;
}

static ssize_t takakrypt_file_read(struct file *file, char __user *buf, 
                                   size_t count, loff_t *ppos)
{
    struct takakrypt_file_context *ctx = file->private_data;
    struct takakrypt_policy_result policy;
    ssize_t ret;
    void *kernel_buf = NULL;
    
    if (!ctx) {
        // File not intercepted, use original operation
        return call_original_read(file, buf, count, ppos);
    }
    
    // Check policy for read operation
    ret = takakrypt_check_policy(ctx->filepath, "read", &policy);
    if (ret < 0 || policy.action != TAKAKRYPT_ACTION_ALLOW) {
        takakrypt_audit_log("Read denied for %s (uid=%u, pid=%u)\n", 
                           ctx->filepath, current_uid().val, current->pid);
        return -EACCES;
    }
    
    // Read encrypted data
    kernel_buf = kmalloc(count, GFP_KERNEL);
    if (!kernel_buf) {
        return -ENOMEM;
    }
    
    ret = call_original_read(file, kernel_buf, count, ppos);
    if (ret <= 0) {
        goto cleanup;
    }
    
    // Decrypt if needed
    if (takakrypt_is_encrypted_file(kernel_buf, ret)) {
        ret = takakrypt_decrypt_data(kernel_buf, ret, &policy, ctx);
        if (ret < 0) {
            goto cleanup;
        }
    }
    
    // Copy to userspace
    if (copy_to_user(buf, kernel_buf, ret)) {
        ret = -EFAULT;
    }
    
cleanup:
    if (kernel_buf) {
        secure_zero_memory(kernel_buf, count);
        kfree(kernel_buf);
    }
    return ret;
}
```

**kprobe Hook Implementation**:

```c
// kprobe_hooks.c - Dynamic kernel probing for global VFS monitoring
static struct kprobe kp_vfs_read = {
    .symbol_name = "vfs_read",
    .pre_handler = pre_vfs_read,
};

static struct kprobe kp_vfs_write = {
    .symbol_name = "vfs_write", 
    .pre_handler = pre_vfs_write,
};

static int pre_vfs_read(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    char __user *buf;
    size_t count;
    loff_t *pos;
    char *filepath;
    
    // Extract parameters from registers (x86_64 calling convention)
    file = (struct file *)regs->di;
    buf = (char __user *)regs->si;
    count = (size_t)regs->dx;
    pos = (loff_t *)regs->cx;
    
    if (!file || !file->f_path.dentry) {
        return 0;
    }
    
    filepath = takakrypt_get_file_path(file);
    if (IS_ERR(filepath)) {
        return 0;
    }
    
    // Check if file should be intercepted
    if (takakrypt_should_intercept_file(filepath, current)) {
        takakrypt_debug("kprobe: Intercepted read for %s\n", filepath);
        // Log or modify behavior as needed
    }
    
    kfree(filepath);
    return 0;
}
```

#### 2. takakryptfs.ko - Stackable Filesystem

**Purpose**: Provides a stackable filesystem for direct VFS operations on mounted paths

**Key Implementation**:

```c
// main_legacy.c - Filesystem registration
static struct file_system_type takakryptfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "takakryptfs",
    .mount = takakryptfs_mount,
    .kill_sb = kill_anon_super,
    .fs_flags = FS_REVAL_DOT,
};

static int __init takakryptfs_init(void)
{
    int ret;
    
    ret = register_filesystem(&takakryptfs_fs_type);
    if (ret) {
        printk(KERN_ERR "takakryptfs: Failed to register filesystem\n");
        return ret;
    }
    
    printk(KERN_INFO "takakryptfs: Stackable filesystem registered\n");
    return 0;
}

// file.c - File operations
static ssize_t takakryptfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakryptfs_file_info *file_info = file->private_data;
    struct takakryptfs_policy_result policy;
    ssize_t ret;
    
    // Policy evaluation
    ret = takakryptfs_evaluate_policy(file, "read", &policy);
    if (ret < 0 || policy.action != TAKAKRYPTFS_ACTION_ALLOW) {
        return -EACCES;
    }
    
    // Read from lower file
    ret = vfs_iter_read(file_info->lower_file, iter, &iocb->ki_pos);
    if (ret <= 0) {
        return ret;
    }
    
    // Decrypt if needed
    if (policy.encryption_enabled) {
        ret = takakryptfs_decrypt_buffer(iter, ret, &policy);
    }
    
    return ret;
}

static ssize_t takakryptfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakryptfs_file_info *file_info = file->private_data;
    struct takakryptfs_policy_result policy;
    ssize_t ret;
    
    // Policy evaluation
    ret = takakryptfs_evaluate_policy(file, "write", &policy);
    if (ret < 0 || policy.action != TAKAKRYPTFS_ACTION_ALLOW) {
        return -EACCES;
    }
    
    // Encrypt if needed
    if (policy.encryption_enabled) {
        ret = takakryptfs_encrypt_buffer(iter, iov_iter_count(iter), &policy);
        if (ret < 0) {
            return ret;
        }
    }
    
    // Write to lower file
    return vfs_iter_write(file_info->lower_file, iter, &iocb->ki_pos);
}
```

### Netlink Communication

**Protocol Implementation**:

```c
// netlink.c - Kernel-userspace communication
static void takakrypt_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct takakrypt_msg_header *msg_header;
    void *payload;
    uint32_t pid;
    
    nlh = nlmsg_hdr(skb);
    pid = NETLINK_CB(skb).portid;
    
    // Validate message
    if (nlmsg_len(nlh) < sizeof(struct takakrypt_msg_header)) {
        takakrypt_error("Invalid message size from PID %u\n", pid);
        return;
    }
    
    msg_header = (struct takakrypt_msg_header *)nlmsg_data(nlh);
    
    // Validate magic and version
    if (msg_header->magic != TAKAKRYPT_MSG_MAGIC ||
        msg_header->version != TAKAKRYPT_PROTOCOL_VERSION) {
        takakrypt_error("Invalid message format from PID %u\n", pid);
        return;
    }
    
    payload = ((char *)msg_header) + sizeof(struct takakrypt_msg_header);
    
    // Dispatch based on operation
    switch (msg_header->operation) {
    case TAKAKRYPT_OP_HEALTH_CHECK:
        takakrypt_handle_health_check(msg_header, pid);
        break;
    case TAKAKRYPT_OP_POLICY_RESPONSE:
        takakrypt_handle_policy_response(msg_header, payload);
        break;
    case TAKAKRYPT_OP_CRYPTO_RESPONSE:
        takakrypt_handle_crypto_response(msg_header, payload);
        break;
    default:
        takakrypt_error("Unknown operation %u from PID %u\n", 
                       msg_header->operation, pid);
    }
}

// Synchronous request/response function
int takakrypt_send_request_and_wait(struct takakrypt_msg_header *msg, 
                                    size_t msg_size, void *response, 
                                    size_t response_size)
{
    struct pending_request *pending_req;
    int ret;
    
    if (!msg || !response) {
        return -EINVAL;
    }
    
    // Check agent connectivity
    if (takakrypt_global_state->agent_pid == 0) {
        takakrypt_debug("No agent connected for request\n");
        return -ENOTCONN;
    }
    
    // Create pending request tracking
    pending_req = takakrypt_create_pending_request(msg->sequence);
    if (!pending_req) {
        return -ENOMEM;
    }
    
    // Send request
    ret = takakrypt_send_request(msg, msg_size);
    if (ret) {
        takakrypt_cleanup_pending_request(pending_req);
        return ret;
    }
    
    // Wait for response with timeout
    ret = takakrypt_wait_for_response(pending_req, 5000); // 5 second timeout
    if (ret == 0 && pending_req->response_data && pending_req->response_size > 0) {
        size_t copy_size = min(response_size, pending_req->response_size);
        memcpy(response, pending_req->response_data, copy_size);
    }
    
    // Cleanup
    takakrypt_cleanup_pending_request(pending_req);
    return ret;
}
```

---

## Userspace Agent Implementation

### Core Architecture

The Takakrypt agent is implemented in Go with a modular architecture:

```
pkg/
├── agent/          // Main agent logic and request handling
├── config/         // Configuration management
├── crypto/         // Encryption engines and key management
├── kms/           // Key Management System integration
├── netlink/       // Kernel communication
├── policy/        // Policy evaluation engine
├── process/       // Process detection and classification
└── logging/       // Audit and operational logging
```

### Main Agent Implementation

```go
// cmd/takakrypt-agent/main.go
package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/takakrypt/pkg/agent"
    "github.com/takakrypt/pkg/config"
    "github.com/takakrypt/pkg/logging"
)

func main() {
    var (
        configPath = flag.String("config", "/etc/takakrypt/config.yaml", 
                                "Path to configuration file")
        logLevel   = flag.String("log-level", "info", 
                                "Log level (debug, info, warn, error)")
        pidFile    = flag.String("pid-file", "/var/run/takakrypt/agent.pid", 
                                "PID file path")
        daemon     = flag.Bool("daemon", false, "Run as daemon")
        version    = flag.Bool("version", false, "Show version and exit")
    )
    flag.Parse()
    
    if *version {
        fmt.Printf("Takakrypt Agent v%s\n", agent.Version)
        os.Exit(0)
    }
    
    // Initialize logging
    logger, err := logging.NewLogger(*logLevel)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
        os.Exit(1)
    }
    
    // Load configuration
    cfg, err := config.LoadFromFile(*configPath)
    if err != nil {
        logger.Fatal("Failed to load configuration", "error", err)
    }
    
    // Create agent
    agentInstance, err := agent.New(cfg, logger)
    if err != nil {
        logger.Fatal("Failed to create agent", "error", err)
    }
    
    // Setup signal handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
    
    go func() {
        for sig := range sigChan {
            switch sig {
            case syscall.SIGHUP:
                logger.Info("Received SIGHUP, reloading configuration")
                if err := agentInstance.ReloadConfig(*configPath); err != nil {
                    logger.Error("Failed to reload configuration", "error", err)
                }
            case syscall.SIGINT, syscall.SIGTERM:
                logger.Info("Received shutdown signal", "signal", sig)
                cancel()
            }
        }
    }()
    
    // Write PID file
    if err := writePIDFile(*pidFile); err != nil {
        logger.Error("Failed to write PID file", "error", err)
    }
    defer os.Remove(*pidFile)
    
    // Start agent
    logger.Info("Starting Takakrypt Transparent Encryption Agent",
               "version", agent.Version,
               "config", *configPath)
    
    if err := agentInstance.Start(ctx); err != nil {
        logger.Fatal("Agent failed", "error", err)
    }
    
    logger.Info("Agent shutdown complete")
}
```

### Agent Core Implementation

```go
// pkg/agent/agent.go
package agent

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/takakrypt/pkg/config"
    "github.com/takakrypt/pkg/crypto"
    "github.com/takakrypt/pkg/kms"
    "github.com/takakrypt/pkg/netlink"
    "github.com/takakrypt/pkg/policy"
    "github.com/takakrypt/pkg/process"
)

type Agent struct {
    config          *config.Config
    logger          Logger
    policyEngine    *policy.Engine
    cryptoEngine    *crypto.Engine
    kmsClient       kms.Client
    netlinkClient   *netlink.Client
    processDetector *process.Detector
    requestHandler  *RequestHandler
    
    mu              sync.RWMutex
    running         bool
    stopChan        chan struct{}
    wg              sync.WaitGroup
}

func New(cfg *config.Config, logger Logger) (*Agent, error) {
    agent := &Agent{
        config:   cfg,
        logger:   logger,
        stopChan: make(chan struct{}),
    }
    
    // Initialize components
    if err := agent.initializeComponents(); err != nil {
        return nil, fmt.Errorf("failed to initialize components: %w", err)
    }
    
    return agent, nil
}

func (a *Agent) initializeComponents() error {
    var err error
    
    // Initialize policy engine
    a.policyEngine, err = policy.NewEngine(a.config.Policies, a.logger)
    if err != nil {
        return fmt.Errorf("failed to initialize policy engine: %w", err)
    }
    
    // Initialize crypto engine
    a.cryptoEngine, err = crypto.NewEngine(a.config.Crypto, a.logger)
    if err != nil {
        return fmt.Errorf("failed to initialize crypto engine: %w", err)
    }
    
    // Initialize KMS client
    a.kmsClient, err = kms.NewClient(a.config.KMS, a.logger)
    if err != nil {
        return fmt.Errorf("failed to initialize KMS client: %w", err)
    }
    
    // Initialize process detector
    a.processDetector, err = process.NewDetector(a.config.ProcessDetection, a.logger)
    if err != nil {
        return fmt.Errorf("failed to initialize process detector: %w", err)
    }
    
    // Initialize netlink client
    a.netlinkClient, err = netlink.NewClient(a.config.Netlink, a.logger)
    if err != nil {
        return fmt.Errorf("failed to initialize netlink client: %w", err)
    }
    
    // Initialize request handler
    a.requestHandler, err = NewRequestHandler(&RequestHandlerConfig{
        PolicyEngine:    a.policyEngine,
        CryptoEngine:    a.cryptoEngine,
        KMSClient:      a.kmsClient,
        ProcessDetector: a.processDetector,
        Logger:         a.logger,
    })
    if err != nil {
        return fmt.Errorf("failed to initialize request handler: %w", err)
    }
    
    return nil
}

func (a *Agent) Start(ctx context.Context) error {
    a.mu.Lock()
    if a.running {
        a.mu.Unlock()
        return fmt.Errorf("agent is already running")
    }
    a.running = true
    a.mu.Unlock()
    
    a.logger.Info("Starting transparent encryption agent")
    
    // Start netlink communication
    a.logger.Info("Connecting to kernel module via netlink")
    if err := a.netlinkClient.Connect(); err != nil {
        return fmt.Errorf("failed to connect to kernel module: %w", err)
    }
    defer a.netlinkClient.Close()
    
    // Start request processing
    a.wg.Add(1)
    go a.processRequests(ctx)
    
    // Start health monitoring
    a.wg.Add(1)
    go a.healthMonitor(ctx)
    
    // Start metrics collection
    if a.config.Metrics.Enabled {
        a.wg.Add(1)
        go a.metricsCollector(ctx)
    }
    
    // Wait for shutdown
    select {
    case <-ctx.Done():
        a.logger.Info("Shutdown requested")
    case <-a.stopChan:
        a.logger.Info("Stop signal received")
    }
    
    // Graceful shutdown
    a.logger.Info("Initiating graceful shutdown")
    a.mu.Lock()
    a.running = false
    a.mu.Unlock()
    
    // Wait for goroutines to finish
    done := make(chan struct{})
    go func() {
        a.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        a.logger.Info("All goroutines stopped")
    case <-time.After(30 * time.Second):
        a.logger.Warn("Forced shutdown after timeout")
    }
    
    return nil
}

func (a *Agent) processRequests(ctx context.Context) {
    defer a.wg.Done()
    
    for {
        select {
        case <-ctx.Done():
            return
        default:
            // Receive request from kernel
            request, err := a.netlinkClient.ReceiveRequest(ctx)
            if err != nil {
                if err != netlink.ErrTimeout {
                    a.logger.Error("Failed to receive request", "error", err)
                }
                continue
            }
            
            // Process request asynchronously
            go func(req *netlink.Request) {
                response, err := a.requestHandler.HandleRequest(ctx, req)
                if err != nil {
                    a.logger.Error("Failed to handle request", 
                                 "request_id", req.ID, "error", err)
                    return
                }
                
                // Send response back to kernel
                if err := a.netlinkClient.SendResponse(response); err != nil {
                    a.logger.Error("Failed to send response", 
                                 "request_id", req.ID, "error", err)
                }
            }(request)
        }
    }
}
```

### Policy Engine Implementation

```go
// pkg/policy/engine.go
package policy

import (
    "context"
    "fmt"
    "strings"
    "time"
    
    "github.com/takakrypt/pkg/config"
    "github.com/takakrypt/pkg/process"
)

type Engine struct {
    policies     map[string]*Policy
    userSets     map[string]*UserSet
    processSets  map[string]*ProcessSet
    resourceSets map[string]*ResourceSet
    timeSets     map[string]*TimeSet
    cache        *PolicyCache
    logger       Logger
}

type AccessContext struct {
    UserID       uint32
    GroupID      uint32
    ProcessID    uint32
    ProcessName  string
    FilePath     string
    Operation    string
    Timestamp    time.Time
    ProcessInfo  *process.Info
    FileInfo     *FileInfo
}

type PolicyDecision struct {
    Action          Action
    EncryptionKey   string
    Algorithm       string
    Policy          *Policy
    Reason          string
    AuditRequired   bool
    TTL             time.Duration
}

func (e *Engine) EvaluateAccess(ctx context.Context, accessCtx *AccessContext) (*PolicyDecision, error) {
    // Check cache first
    if decision := e.cache.Get(accessCtx); decision != nil {
        return decision, nil
    }
    
    // Enrich context with additional information
    if err := e.enrichContext(accessCtx); err != nil {
        return nil, fmt.Errorf("failed to enrich context: %w", err)
    }
    
    // Find applicable policies
    applicablePolicies := e.findApplicablePolicies(accessCtx)
    if len(applicablePolicies) == 0 {
        decision := &PolicyDecision{
            Action: ActionDeny,
            Reason: "No applicable policies found",
            AuditRequired: true,
        }
        e.cache.Set(accessCtx, decision)
        return decision, nil
    }
    
    // Evaluate policies in priority order
    for _, policy := range applicablePolicies {
        if decision := e.evaluatePolicy(policy, accessCtx); decision != nil {
            e.cache.Set(accessCtx, decision)
            return decision, nil
        }
    }
    
    // Default deny
    decision := &PolicyDecision{
        Action: ActionDeny,
        Reason: "No policies matched",
        AuditRequired: true,
    }
    e.cache.Set(accessCtx, decision)
    return decision, nil
}

func (e *Engine) evaluatePolicy(policy *Policy, ctx *AccessContext) *PolicyDecision {
    // Evaluate user sets
    if !e.evaluateUserSets(policy.UserSets, ctx) {
        return nil
    }
    
    // Evaluate process sets
    if !e.evaluateProcessSets(policy.ProcessSets, ctx) {
        return nil
    }
    
    // Evaluate resource sets
    if !e.evaluateResourceSets(policy.ResourceSets, ctx) {
        return nil
    }
    
    // Evaluate time windows
    if !e.evaluateTimeSets(policy.TimeSets, ctx) {
        return nil
    }
    
    // Evaluate additional conditions
    if !e.evaluateConditions(policy.Conditions, ctx) {
        return nil
    }
    
    // Policy matches, return decision
    return &PolicyDecision{
        Action:        policy.Action,
        EncryptionKey: policy.EncryptionKey,
        Algorithm:     policy.Algorithm,
        Policy:        policy,
        Reason:        fmt.Sprintf("Matched policy: %s", policy.Name),
        AuditRequired: policy.AuditRequired,
        TTL:           time.Duration(policy.CacheTTL) * time.Second,
    }
}

func (e *Engine) evaluateUserSets(userSetNames []string, ctx *AccessContext) bool {
    if len(userSetNames) == 0 {
        return true // No user restrictions
    }
    
    for _, userSetName := range userSetNames {
        userSet, exists := e.userSets[userSetName]
        if !exists {
            continue
        }
        
        if e.userMatchesSet(userSet, ctx) {
            return true
        }
    }
    
    return false
}

func (e *Engine) evaluateProcessSets(processSetNames []string, ctx *AccessContext) bool {
    if len(processSetNames) == 0 {
        return true // No process restrictions
    }
    
    for _, processSetName := range processSetNames {
        processSet, exists := e.processSets[processSetName]
        if !exists {
            continue
        }
        
        if e.processMatchesSet(processSet, ctx) {
            return true
        }
    }
    
    return false
}

func (e *Engine) processMatchesSet(processSet *ProcessSet, ctx *AccessContext) bool {
    // Match by process name
    for _, pattern := range processSet.ProcessNames {
        if matched, _ := filepath.Match(pattern, ctx.ProcessName); matched {
            return true
        }
    }
    
    // Match by process type (if detected)
    if ctx.ProcessInfo != nil {
        for _, processType := range processSet.ProcessTypes {
            if ctx.ProcessInfo.Type == processType {
                return true
            }
        }
        
        // Match by database type
        if ctx.ProcessInfo.DatabaseType != "" {
            for _, dbType := range processSet.DatabaseTypes {
                if ctx.ProcessInfo.DatabaseType == dbType {
                    return true
                }
            }
        }
    }
    
    // Match by executable path
    for _, pattern := range processSet.ExecutablePaths {
        if matched, _ := filepath.Match(pattern, ctx.ProcessInfo.ExecutablePath); matched {
            return true
        }
    }
    
    return false
}
```

### Encryption Engine Implementation

```go
// pkg/crypto/engine.go
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
)

type Engine struct {
    keyCache map[string][]byte
    kms      KMSClient
    logger   Logger
}

type EncryptionRequest struct {
    Data      []byte
    KeyID     string
    Algorithm string
    FilePath  string
    Metadata  map[string]string
}

type EncryptionResponse struct {
    EncryptedData []byte
    KeyID         string
    IV            []byte
    AuthTag       []byte
    Algorithm     string
}

func (e *Engine) Encrypt(req *EncryptionRequest) (*EncryptionResponse, error) {
    // Get encryption key
    key, err := e.getKey(req.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to get encryption key: %w", err)
    }
    
    switch req.Algorithm {
    case "AES-256-GCM":
        return e.encryptAESGCM(req.Data, key, req)
    default:
        return nil, fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
    }
}

func (e *Engine) encryptAESGCM(data, key []byte, req *EncryptionRequest) (*EncryptionResponse, error) {
    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create AES cipher: %w", err)
    }
    
    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM mode: %w", err)
    }
    
    // Generate random nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    // Prepare additional authenticated data
    aad := e.buildAAD(req.FilePath, req.Metadata)
    
    // Encrypt and authenticate
    ciphertext := gcm.Seal(nil, nonce, data, aad)
    
    // Split ciphertext and auth tag
    authTagSize := gcm.Overhead()
    encryptedData := ciphertext[:len(ciphertext)-authTagSize]
    authTag := ciphertext[len(ciphertext)-authTagSize:]
    
    return &EncryptionResponse{
        EncryptedData: encryptedData,
        KeyID:         req.KeyID,
        IV:            nonce,
        AuthTag:       authTag,
        Algorithm:     req.Algorithm,
    }, nil
}

func (e *Engine) Decrypt(encryptedData []byte, keyID string, iv, authTag []byte, 
                        algorithm, filePath string, metadata map[string]string) ([]byte, error) {
    // Get decryption key
    key, err := e.getKey(keyID)
    if err != nil {
        return nil, fmt.Errorf("failed to get decryption key: %w", err)
    }
    
    switch algorithm {
    case "AES-256-GCM":
        return e.decryptAESGCM(encryptedData, key, iv, authTag, filePath, metadata)
    default:
        return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
    }
}

func (e *Engine) decryptAESGCM(encryptedData, key, iv, authTag []byte, 
                              filePath string, metadata map[string]string) ([]byte, error) {
    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create AES cipher: %w", err)
    }
    
    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM mode: %w", err)
    }
    
    // Reconstruct ciphertext with auth tag
    ciphertext := append(encryptedData, authTag...)
    
    // Prepare additional authenticated data
    aad := e.buildAAD(filePath, metadata)
    
    // Decrypt and verify
    plaintext, err := gcm.Open(nil, iv, ciphertext, aad)
    if err != nil {
        return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
    }
    
    return plaintext, nil
}

func (e *Engine) buildAAD(filePath string, metadata map[string]string) []byte {
    // Build additional authenticated data from file path and metadata
    aad := fmt.Sprintf("path:%s", filePath)
    for key, value := range metadata {
        aad += fmt.Sprintf("|%s:%s", key, value)
    }
    return []byte(aad)
}
```

### File Format Implementation

```go
// pkg/crypto/file_format.go
package crypto

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

const (
    TAKAMagic   = "TAKA"
    TAKAVersion = 1
    
    // Header layout
    MagicOffset       = 0
    VersionOffset     = 4
    AlgorithmOffset   = 8
    KeyIDLenOffset    = 12
    KeyIDOffset       = 16
    // Variable fields follow based on KeyID length
)

type TAKAHeader struct {
    Magic        [4]byte
    Version      uint32
    Algorithm    uint32
    KeyIDLength  uint32
    KeyID        string
    IV           []byte
    AuthTag      []byte
    OriginalSize uint64
    Flags        uint32
    Reserved     [16]byte
}

func (h *TAKAHeader) Marshal() ([]byte, error) {
    var buf bytes.Buffer
    
    // Write fixed fields
    buf.Write(h.Magic[:])
    binary.Write(&buf, binary.LittleEndian, h.Version)
    binary.Write(&buf, binary.LittleEndian, h.Algorithm)
    binary.Write(&buf, binary.LittleEndian, h.KeyIDLength)
    
    // Write variable fields
    buf.WriteString(h.KeyID)
    buf.Write(h.IV)
    buf.Write(h.AuthTag)
    binary.Write(&buf, binary.LittleEndian, h.OriginalSize)
    binary.Write(&buf, binary.LittleEndian, h.Flags)
    buf.Write(h.Reserved[:])
    
    return buf.Bytes(), nil
}

func (h *TAKAHeader) Unmarshal(data []byte) error {
    if len(data) < 16 {
        return fmt.Errorf("header too short")
    }
    
    buf := bytes.NewReader(data)
    
    // Read fixed fields
    buf.Read(h.Magic[:])
    binary.Read(buf, binary.LittleEndian, &h.Version)
    binary.Read(buf, binary.LittleEndian, &h.Algorithm)
    binary.Read(buf, binary.LittleEndian, &h.KeyIDLength)
    
    // Validate
    if string(h.Magic[:]) != TAKAMagic {
        return fmt.Errorf("invalid magic: %s", string(h.Magic[:]))
    }
    
    if h.Version != TAKAVersion {
        return fmt.Errorf("unsupported version: %d", h.Version)
    }
    
    if h.KeyIDLength > 256 {
        return fmt.Errorf("key ID too long: %d", h.KeyIDLength)
    }
    
    // Read variable fields
    keyIDBytes := make([]byte, h.KeyIDLength)
    buf.Read(keyIDBytes)
    h.KeyID = string(keyIDBytes)
    
    // Read IV (12 bytes for GCM)
    h.IV = make([]byte, 12)
    buf.Read(h.IV)
    
    // Read auth tag (16 bytes for GCM)
    h.AuthTag = make([]byte, 16)
    buf.Read(h.AuthTag)
    
    // Read remaining fields
    binary.Read(buf, binary.LittleEndian, &h.OriginalSize)
    binary.Read(buf, binary.LittleEndian, &h.Flags)
    buf.Read(h.Reserved[:])
    
    return nil
}

func (e *Engine) CreateEncryptedFile(plaintext []byte, keyID string) ([]byte, error) {
    // Encrypt data
    encResp, err := e.Encrypt(&EncryptionRequest{
        Data:      plaintext,
        KeyID:     keyID,
        Algorithm: "AES-256-GCM",
    })
    if err != nil {
        return nil, err
    }
    
    // Create header
    header := &TAKAHeader{
        Magic:        [4]byte{'T', 'A', 'K', 'A'},
        Version:      TAKAVersion,
        Algorithm:    1, // AES-256-GCM
        KeyIDLength:  uint32(len(encResp.KeyID)),
        KeyID:        encResp.KeyID,
        IV:           encResp.IV,
        AuthTag:      encResp.AuthTag,
        OriginalSize: uint64(len(plaintext)),
        Flags:        0,
    }
    
    // Marshal header
    headerBytes, err := header.Marshal()
    if err != nil {
        return nil, err
    }
    
    // Combine header and encrypted data
    result := make([]byte, len(headerBytes)+len(encResp.EncryptedData))
    copy(result, headerBytes)
    copy(result[len(headerBytes):], encResp.EncryptedData)
    
    return result, nil
}

func (e *Engine) ReadEncryptedFile(encryptedFile []byte, filePath string) ([]byte, error) {
    // Parse header
    header := &TAKAHeader{}
    if err := header.Unmarshal(encryptedFile); err != nil {
        return nil, fmt.Errorf("failed to parse header: %w", err)
    }
    
    // Calculate header size
    headerSize := 16 + len(header.KeyID) + 12 + 16 + 8 + 4 + 16
    
    if len(encryptedFile) < headerSize {
        return nil, fmt.Errorf("file too short")
    }
    
    // Extract encrypted data
    encryptedData := encryptedFile[headerSize:]
    
    // Decrypt
    algorithm := "AES-256-GCM" // Map from header.Algorithm
    plaintext, err := e.Decrypt(encryptedData, header.KeyID, header.IV, 
                               header.AuthTag, algorithm, filePath, nil)
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }
    
    return plaintext, nil
}
```

---

## Communication Protocols

### Netlink Protocol Specification

#### Message Format

```c
struct takakrypt_msg_header {
    uint32_t magic;           // 0x54414B41 ("TAKA")
    uint32_t version;         // Protocol version (currently 1)
    uint32_t operation;       // Operation type (see below)
    uint32_t sequence;        // Sequence number for request/response matching
    uint32_t payload_size;    // Size of payload following header
    uint64_t timestamp;       // Unix timestamp in microseconds
    uint32_t status;          // Status code (0 = success)
    uint32_t reserved;        // Reserved for future use
};
```

#### Operation Types

| Operation | Value | Description | Direction |
|-----------|-------|-------------|-----------|
| HEALTH_CHECK | 0 | System health verification | Bidirectional |
| CHECK_POLICY | 1 | Policy evaluation request | Kernel → Agent |
| ENCRYPT_DATA | 2 | Encryption operation | Kernel → Agent |
| DECRYPT_DATA | 3 | Decryption operation | Kernel → Agent |
| GET_STATUS | 4 | System status query | Agent → Kernel |
| UPDATE_CONFIG | 5 | Configuration update | Agent → Kernel |
| POLICY_RESPONSE | 6 | Policy decision response | Agent → Kernel |
| CRYPTO_RESPONSE | 7 | Crypto operation response | Agent → Kernel |

#### Status Codes

```c
#define TAKAKRYPT_STATUS_SUCCESS           0
#define TAKAKRYPT_STATUS_ERROR             1
#define TAKAKRYPT_STATUS_PERMISSION_DENIED 2
#define TAKAKRYPT_STATUS_NOT_FOUND         3
#define TAKAKRYPT_STATUS_INVALID_REQUEST   4
#define TAKAKRYPT_STATUS_TIMEOUT           5
#define TAKAKRYPT_STATUS_NO_AGENT          6
```

#### Payload Structures

**Policy Check Request**:
```c
struct takakrypt_policy_request {
    uint32_t uid;                    // User ID
    uint32_t gid;                    // Group ID  
    uint32_t pid;                    // Process ID
    uint32_t operation_flags;        // Read/Write/Create flags
    uint32_t filepath_len;           // Length of filepath
    char filepath[];                 // Null-terminated file path
    // Additional context data follows
};
```

**Policy Check Response**:
```c
struct takakrypt_policy_response {
    uint32_t action;                 // Allow/Deny/Encrypt
    uint32_t encryption_required;    // Boolean flag
    uint32_t key_id_len;            // Length of key identifier
    char key_id[];                  // Key identifier string
    uint32_t algorithm;             // Encryption algorithm
    uint64_t cache_ttl;             // Cache TTL in seconds
};
```

**Encryption Request**:
```c
struct takakrypt_encrypt_request {
    uint32_t key_id_len;            // Length of key identifier
    char key_id[];                  // Key identifier
    uint32_t algorithm;             // Encryption algorithm
    uint32_t data_len;              // Length of data to encrypt
    uint8_t data[];                 // Data to encrypt
    // Metadata follows
};
```

### Request Flow Implementation

```go
// pkg/netlink/client_linux.go
package netlink

import (
    "context"
    "fmt"
    "net"
    "syscall"
    "time"
    "unsafe"
)

type Client struct {
    socket     int
    addr       *syscall.SockaddrNetlink
    logger     Logger
    msgSeq     uint32
    requests   map[uint32]*PendingRequest
    requestsMu sync.RWMutex
}

type PendingRequest struct {
    Sequence    uint32
    ResponseCh  chan *Response
    Timeout     time.Duration
    CreatedAt   time.Time
}

func (c *Client) SendRequest(req *Request) (*Response, error) {
    // Prepare message
    msg := &MessageHeader{
        Magic:       TAKAMagic,
        Version:     TAKAVersion,
        Operation:   req.Operation,
        Sequence:    atomic.AddUint32(&c.msgSeq, 1),
        PayloadSize: uint32(len(req.Payload)),
        Timestamp:   uint64(time.Now().UnixMicro()),
        Status:      0,
        Reserved:    0,
    }
    
    // Marshal message
    msgBytes, err := msg.Marshal()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Combine header and payload
    fullMsg := append(msgBytes, req.Payload...)
    
    // Create pending request
    pending := &PendingRequest{
        Sequence:   msg.Sequence,
        ResponseCh: make(chan *Response, 1),
        Timeout:    30 * time.Second,
        CreatedAt:  time.Now(),
    }
    
    c.requestsMu.Lock()
    c.requests[msg.Sequence] = pending
    c.requestsMu.Unlock()
    
    // Send via netlink
    err = syscall.Sendto(c.socket, fullMsg, 0, c.addr)
    if err != nil {
        c.cleanupRequest(msg.Sequence)
        return nil, fmt.Errorf("failed to send netlink message: %w", err)
    }
    
    // Wait for response
    select {
    case resp := <-pending.ResponseCh:
        c.cleanupRequest(msg.Sequence)
        return resp, nil
    case <-time.After(pending.Timeout):
        c.cleanupRequest(msg.Sequence)
        return nil, fmt.Errorf("request timeout")
    }
}

func (c *Client) receiveLoop() {
    buffer := make([]byte, 65536)
    
    for {
        n, err := syscall.Recvfrom(c.socket, buffer, 0)
        if err != nil {
            c.logger.Error("Failed to receive netlink message", "error", err)
            continue
        }
        
        if n < int(unsafe.Sizeof(MessageHeader{})) {
            c.logger.Warn("Received message too short", "size", n)
            continue
        }
        
        // Parse header
        header := &MessageHeader{}
        if err := header.Unmarshal(buffer[:n]); err != nil {
            c.logger.Error("Failed to parse message header", "error", err)
            continue
        }
        
        // Validate
        if header.Magic != TAKAMagic || header.Version != TAKAVersion {
            c.logger.Warn("Invalid message format", 
                         "magic", header.Magic, "version", header.Version)
            continue
        }
        
        // Extract payload
        headerSize := int(unsafe.Sizeof(MessageHeader{}))
        payload := buffer[headerSize:headerSize+int(header.PayloadSize)]
        
        // Dispatch response
        c.handleResponse(&Response{
            Header:  header,
            Payload: payload,
        })
    }
}

func (c *Client) handleResponse(resp *Response) {
    c.requestsMu.RLock()
    pending, exists := c.requests[resp.Header.Sequence]
    c.requestsMu.RUnlock()
    
    if !exists {
        c.logger.Warn("Received response for unknown request", 
                     "sequence", resp.Header.Sequence)
        return
    }
    
    select {
    case pending.ResponseCh <- resp:
        // Response delivered
    default:
        c.logger.Warn("Response channel full, dropping response",
                     "sequence", resp.Header.Sequence)
    }
}
```

---

## Data Structures and Algorithms

### Kernel Data Structures

```c
// takakrypt.h - Core data structures

// Global module state
struct takakrypt_state {
    // Module information
    atomic_t module_active;
    unsigned long start_time;
    uint32_t agent_pid;
    
    // Netlink communication
    struct sock *netlink_sock;
    uint32_t sequence_counter;
    
    // Statistics
    struct takakrypt_stats stats;
    spinlock_t stats_lock;
    
    // Caches
    struct takakrypt_cache *policy_cache;
    struct takakrypt_cache *file_cache;
    struct takakrypt_cache *key_cache;
    
    // Active file contexts
    struct list_head file_contexts;
    spinlock_t file_contexts_lock;
    
    // Work queue for async operations
    struct workqueue_struct *workqueue;
};

// Per-file context
struct takakrypt_file_context {
    struct list_head list;
    struct file *file;
    char *filepath;
    struct takakrypt_policy_result policy;
    atomic_t ref_count;
    unsigned long created_at;
    unsigned long last_accessed;
    uint32_t flags;
    void *crypto_context;
};

// Policy cache entry
struct takakrypt_policy_cache_entry {
    struct hlist_node node;
    uint64_t key_hash;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    char *filepath;
    char *operation;
    struct takakrypt_policy_result result;
    unsigned long expires;
    atomic_t ref_count;
};

// Cache implementation
struct takakrypt_cache {
    struct hlist_head *buckets;
    uint32_t bucket_count;
    atomic_t entry_count;
    uint32_t max_entries;
    spinlock_t lock;
    
    // Statistics
    atomic64_t hits;
    atomic64_t misses;
    atomic64_t evictions;
};

// Pending request tracking
struct pending_request {
    struct list_head list;
    uint32_t sequence;
    wait_queue_head_t wait_queue;
    void *response_data;
    size_t response_size;
    int response_status;
    unsigned long timestamp;
    atomic_t completed;
};
```

### Hash Table Implementation

```c
// cache.c - High-performance caching

#define TAKAKRYPT_CACHE_BUCKET_COUNT 1024
#define TAKAKRYPT_CACHE_MAX_ENTRIES  10000

static uint64_t takakrypt_hash_policy_key(uint32_t uid, uint32_t gid, 
                                         uint32_t pid, const char *filepath, 
                                         const char *operation)
{
    uint64_t hash = 14695981039346656037ULL; // FNV-1a offset basis
    const uint64_t prime = 1099511628211ULL; // FNV-1a prime
    
    // Hash UID, GID, PID
    hash ^= uid;
    hash *= prime;
    hash ^= gid;
    hash *= prime;
    hash ^= pid;
    hash *= prime;
    
    // Hash filepath
    const char *p = filepath;
    while (*p) {
        hash ^= (uint8_t)*p++;
        hash *= prime;
    }
    
    // Hash operation
    p = operation;
    while (*p) {
        hash ^= (uint8_t)*p++;
        hash *= prime;
    }
    
    return hash;
}

static struct takakrypt_policy_cache_entry *
takakrypt_cache_lookup(struct takakrypt_cache *cache, uint64_t key_hash,
                      uint32_t uid, uint32_t gid, uint32_t pid,
                      const char *filepath, const char *operation)
{
    uint32_t bucket = key_hash % cache->bucket_count;
    struct hlist_head *head = &cache->buckets[bucket];
    struct takakrypt_policy_cache_entry *entry;
    
    spin_lock(&cache->lock);
    
    hlist_for_each_entry(entry, head, node) {
        if (entry->key_hash == key_hash &&
            entry->uid == uid &&
            entry->gid == gid &&
            entry->pid == pid &&
            strcmp(entry->filepath, filepath) == 0 &&
            strcmp(entry->operation, operation) == 0) {
            
            // Check expiration
            if (time_after(jiffies, entry->expires)) {
                hlist_del(&entry->node);
                atomic_dec(&cache->entry_count);
                atomic64_inc(&cache->evictions);
                kfree(entry->filepath);
                kfree(entry);
                spin_unlock(&cache->lock);
                atomic64_inc(&cache->misses);
                return NULL;
            }
            
            atomic_inc(&entry->ref_count);
            atomic64_inc(&cache->hits);
            spin_unlock(&cache->lock);
            return entry;
        }
    }
    
    spin_unlock(&cache->lock);
    atomic64_inc(&cache->misses);
    return NULL;
}

static int takakrypt_cache_insert(struct takakrypt_cache *cache,
                                 uint64_t key_hash,
                                 uint32_t uid, uint32_t gid, uint32_t pid,
                                 const char *filepath, const char *operation,
                                 struct takakrypt_policy_result *result,
                                 unsigned long ttl)
{
    struct takakrypt_policy_cache_entry *entry;
    uint32_t bucket = key_hash % cache->bucket_count;
    struct hlist_head *head = &cache->buckets[bucket];
    
    // Check cache limits
    if (atomic_read(&cache->entry_count) >= cache->max_entries) {
        takakrypt_cache_evict_lru(cache);
    }
    
    // Allocate entry
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    
    entry->filepath = kstrdup(filepath, GFP_KERNEL);
    if (!entry->filepath) {
        kfree(entry);
        return -ENOMEM;
    }
    
    // Initialize entry
    entry->key_hash = key_hash;
    entry->uid = uid;
    entry->gid = gid;
    entry->pid = pid;
    entry->result = *result;
    entry->expires = jiffies + ttl * HZ;
    atomic_set(&entry->ref_count, 1);
    
    // Insert into hash table
    spin_lock(&cache->lock);
    hlist_add_head(&entry->node, head);
    atomic_inc(&cache->entry_count);
    spin_unlock(&cache->lock);
    
    return 0;
}
```

### Memory Management

```c
// file_context.c - File context management

static struct kmem_cache *file_context_cache;

int takakrypt_file_context_init(void)
{
    file_context_cache = kmem_cache_create("takakrypt_file_context",
                                          sizeof(struct takakrypt_file_context),
                                          0, SLAB_HWCACHE_ALIGN, NULL);
    if (!file_context_cache) {
        return -ENOMEM;
    }
    return 0;
}

void takakrypt_file_context_cleanup(void)
{
    if (file_context_cache) {
        kmem_cache_destroy(file_context_cache);
        file_context_cache = NULL;
    }
}

struct takakrypt_file_context *
takakrypt_create_file_context(struct file *file, const char *filepath)
{
    struct takakrypt_file_context *ctx;
    
    ctx = kmem_cache_alloc(file_context_cache, GFP_KERNEL);
    if (!ctx) {
        return ERR_PTR(-ENOMEM);
    }
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->file = file;
    ctx->filepath = kstrdup(filepath, GFP_KERNEL);
    if (!ctx->filepath) {
        kmem_cache_free(file_context_cache, ctx);
        return ERR_PTR(-ENOMEM);
    }
    
    atomic_set(&ctx->ref_count, 1);
    ctx->created_at = jiffies;
    ctx->last_accessed = jiffies;
    
    // Add to global list
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    list_add(&ctx->list, &takakrypt_global_state->file_contexts);
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    return ctx;
}

void takakrypt_put_file_context(struct takakrypt_file_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    if (atomic_dec_and_test(&ctx->ref_count)) {
        // Remove from global list
        spin_lock(&takakrypt_global_state->file_contexts_lock);
        list_del(&ctx->list);
        spin_unlock(&takakrypt_global_state->file_contexts_lock);
        
        // Free resources
        kfree(ctx->filepath);
        if (ctx->crypto_context) {
            takakrypt_free_crypto_context(ctx->crypto_context);
        }
        
        kmem_cache_free(file_context_cache, ctx);
    }
}
```

### Locking Strategy

```c
// Locking hierarchy (to prevent deadlocks):
// 1. takakrypt_global_state->stats_lock (leaf lock)
// 2. takakrypt_global_state->file_contexts_lock
// 3. takakrypt_cache->lock
// 4. pending_requests_lock

// RCU usage for read-heavy operations
static struct takakrypt_policy_cache_entry *
takakrypt_cache_lookup_rcu(struct takakrypt_cache *cache, uint64_t key_hash)
{
    uint32_t bucket = key_hash % cache->bucket_count;
    struct hlist_head *head = &cache->buckets[bucket];
    struct takakrypt_policy_cache_entry *entry;
    
    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, head, node) {
        if (entry->key_hash == key_hash) {
            if (time_after(jiffies, entry->expires)) {
                entry = NULL;
                break;
            }
            
            // Try to acquire reference
            if (!atomic_inc_not_zero(&entry->ref_count)) {
                entry = NULL;
                break;
            }
            break;
        }
    }
    rcu_read_unlock();
    
    return entry;
}
```

---

## Security Implementation

### Cryptographic Implementation

#### Key Management

```go
// pkg/crypto/keys.go
package crypto

import (
    "crypto/rand"
    "crypto/subtle"
    "fmt"
    "sync"
    "time"
)

type KeyManager struct {
    keys     map[string]*EncryptionKey
    keysMu   sync.RWMutex
    kms      KMSClient
    logger   Logger
}

type EncryptionKey struct {
    ID        string
    Key       []byte
    Algorithm string
    CreatedAt time.Time
    ExpiresAt time.Time
    UsageCount int64
    mu        sync.RWMutex
}

func (km *KeyManager) GetKey(keyID string) (*EncryptionKey, error) {
    // Try cache first
    km.keysMu.RLock()
    if key, exists := km.keys[keyID]; exists {
        key.mu.RLock()
        if time.Now().Before(key.ExpiresAt) {
            key.mu.RUnlock()
            km.keysMu.RUnlock()
            
            // Increment usage counter
            key.mu.Lock()
            key.UsageCount++
            key.mu.Unlock()
            
            return key, nil
        }
        key.mu.RUnlock()
    }
    km.keysMu.RUnlock()
    
    // Fetch from KMS
    keyData, err := km.kms.GetKey(keyID)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch key from KMS: %w", err)
    }
    
    // Create key object
    key := &EncryptionKey{
        ID:        keyID,
        Key:       keyData,
        Algorithm: "AES-256-GCM",
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(1 * time.Hour), // Cache for 1 hour
        UsageCount: 1,
    }
    
    // Store in cache
    km.keysMu.Lock()
    km.keys[keyID] = key
    km.keysMu.Unlock()
    
    return key, nil
}

func (km *KeyManager) secureErase(data []byte) {
    // Secure memory erasure
    for i := range data {
        data[i] = 0
    }
    
    // Additional passes for extra security
    for i := range data {
        data[i] = 0xFF
    }
    for i := range data {
        data[i] = 0xAA
    }
    for i := range data {
        data[i] = 0x55
    }
    for i := range data {
        data[i] = 0
    }
}

func (k *EncryptionKey) Destroy() {
    k.mu.Lock()
    defer k.mu.Unlock()
    
    if k.Key != nil {
        // Secure erase key material
        for i := 0; i < 10; i++ {
            for j := range k.Key {
                k.Key[j] = byte(rand.Intn(256))
            }
        }
        k.Key = nil
    }
}
```

#### Secure Random Number Generation

```go
// pkg/crypto/random.go
package crypto

import (
    "crypto/rand"
    "fmt"
    "io"
)

type SecureRandom struct {
    entropy io.Reader
}

func NewSecureRandom() *SecureRandom {
    return &SecureRandom{
        entropy: rand.Reader,
    }
}

func (sr *SecureRandom) GenerateNonce(size int) ([]byte, error) {
    nonce := make([]byte, size)
    if _, err := io.ReadFull(sr.entropy, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    return nonce, nil
}

func (sr *SecureRandom) GenerateKey(size int) ([]byte, error) {
    key := make([]byte, size)
    if _, err := io.ReadFull(sr.entropy, key); err != nil {
        return nil, fmt.Errorf("failed to generate key: %w", err)
    }
    return key, nil
}

func (sr *SecureRandom) GenerateKeyID() (string, error) {
    // Generate 16 random bytes for key ID
    idBytes := make([]byte, 16)
    if _, err := io.ReadFull(sr.entropy, idBytes); err != nil {
        return "", fmt.Errorf("failed to generate key ID: %w", err)
    }
    
    // Encode as hex
    return fmt.Sprintf("%x", idBytes), nil
}
```

### Access Control

```go
// pkg/policy/access_control.go
package policy

import (
    "fmt"
    "os/user"
    "strconv"
    "syscall"
)

type AccessController struct {
    policies map[string]*AccessPolicy
    logger   Logger
}

type AccessPolicy struct {
    Name        string
    AllowedUIDs []uint32
    AllowedGIDs []uint32
    RequiredCaps []string
    TimeRestrictions *TimeRestrictions
}

func (ac *AccessController) CheckAccess(ctx *AccessContext) error {
    // Check user permissions
    if err := ac.checkUserPermissions(ctx); err != nil {
        return fmt.Errorf("user permission check failed: %w", err)
    }
    
    // Check process capabilities
    if err := ac.checkCapabilities(ctx); err != nil {
        return fmt.Errorf("capability check failed: %w", err)
    }
    
    // Check time restrictions
    if err := ac.checkTimeRestrictions(ctx); err != nil {
        return fmt.Errorf("time restriction check failed: %w", err)
    }
    
    return nil
}

func (ac *AccessController) checkUserPermissions(ctx *AccessContext) error {
    // Get user information
    u, err := user.LookupId(strconv.Itoa(int(ctx.UserID)))
    if err != nil {
        return fmt.Errorf("failed to lookup user: %w", err)
    }
    
    // Check if user is in allowed list
    for _, policy := range ac.policies {
        for _, allowedUID := range policy.AllowedUIDs {
            if ctx.UserID == allowedUID {
                return nil // Access granted
            }
        }
        
        for _, allowedGID := range policy.AllowedGIDs {
            if ctx.GroupID == allowedGID {
                return nil // Access granted
            }
        }
    }
    
    return fmt.Errorf("user %s (UID: %d) not in allowed list", u.Username, ctx.UserID)
}

func (ac *AccessController) checkCapabilities(ctx *AccessContext) error {
    // Check if process has required capabilities
    caps, err := getProcessCapabilities(ctx.ProcessID)
    if err != nil {
        return fmt.Errorf("failed to get process capabilities: %w", err)
    }
    
    // Verify required capabilities
    for _, policy := range ac.policies {
        for _, requiredCap := range policy.RequiredCaps {
            if !hasCapability(caps, requiredCap) {
                return fmt.Errorf("process missing required capability: %s", requiredCap)
            }
        }
    }
    
    return nil
}

func getProcessCapabilities(pid uint32) (map[string]bool, error) {
    // Read capabilities from /proc/PID/status
    statusFile := fmt.Sprintf("/proc/%d/status", pid)
    data, err := os.ReadFile(statusFile)
    if err != nil {
        return nil, err
    }
    
    caps := make(map[string]bool)
    lines := strings.Split(string(data), "\n")
    
    for _, line := range lines {
        if strings.HasPrefix(line, "CapEff:") {
            capHex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
            capValue, err := strconv.ParseUint(capHex, 16, 64)
            if err != nil {
                return nil, err
            }
            
            // Parse capability bits
            for i := 0; i < 64; i++ {
                if (capValue & (1 << uint(i))) != 0 {
                    capName := getCapabilityName(i)
                    if capName != "" {
                        caps[capName] = true
                    }
                }
            }
            break
        }
    }
    
    return caps, nil
}
```

### Audit Logging

```go
// pkg/logging/audit.go
package logging

import (
    "encoding/json"
    "fmt"
    "os"
    "sync"
    "time"
)

type AuditLogger struct {
    file   *os.File
    mu     sync.Mutex
    config *AuditConfig
}

type AuditEvent struct {
    Timestamp    time.Time `json:"timestamp"`
    EventType    string    `json:"event_type"`
    UserID       uint32    `json:"user_id"`
    Username     string    `json:"username"`
    ProcessID    uint32    `json:"process_id"`
    ProcessName  string    `json:"process_name"`
    FilePath     string    `json:"file_path"`
    Operation    string    `json:"operation"`
    Decision     string    `json:"decision"`
    PolicyName   string    `json:"policy_name"`
    EncryptionKey string   `json:"encryption_key_id,omitempty"`
    Result       string    `json:"result"`
    ErrorMessage string    `json:"error_message,omitempty"`
    Duration     int64     `json:"duration_microseconds"`
    SourceIP     string    `json:"source_ip,omitempty"`
    SessionID    string    `json:"session_id,omitempty"`
}

func (al *AuditLogger) LogFileAccess(event *AuditEvent) error {
    al.mu.Lock()
    defer al.mu.Unlock()
    
    // Ensure required fields
    if event.Timestamp.IsZero() {
        event.Timestamp = time.Now()
    }
    
    // Serialize to JSON
    eventJSON, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to serialize audit event: %w", err)
    }
    
    // Write to audit log
    if _, err := al.file.WriteString(string(eventJSON) + "\n"); err != nil {
        return fmt.Errorf("failed to write audit event: %w", err)
    }
    
    // Force sync for critical events
    if event.Decision == "DENY" || event.Result == "ERROR" {
        al.file.Sync()
    }
    
    return nil
}

func (al *AuditLogger) LogPolicyViolation(violation *PolicyViolation) error {
    event := &AuditEvent{
        Timestamp:    time.Now(),
        EventType:    "POLICY_VIOLATION",
        UserID:       violation.UserID,
        Username:     violation.Username,
        ProcessID:    violation.ProcessID,
        ProcessName:  violation.ProcessName,
        FilePath:     violation.FilePath,
        Operation:    violation.Operation,
        Decision:     "DENY",
        PolicyName:   violation.PolicyName,
        Result:       "VIOLATION",
        ErrorMessage: violation.Reason,
        SourceIP:     violation.SourceIP,
        SessionID:    violation.SessionID,
    }
    
    return al.LogFileAccess(event)
}

// CEF (Common Event Format) output for SIEM integration
func (al *AuditLogger) FormatCEF(event *AuditEvent) string {
    return fmt.Sprintf("CEF:0|Takakrypt|Transparent Encryption|1.0|%s|%s|%d|"+
        "src=%s suser=%s duser=%s fname=%s act=%s outcome=%s "+
        "cs1Label=Policy cs1=%s cs2Label=EncryptionKey cs2=%s "+
        "cn1Label=Duration cn1=%d msg=%s",
        event.EventType,
        "File Access Event",
        al.getSeverity(event),
        event.SourceIP,
        event.Username,
        event.Username,
        event.FilePath,
        event.Operation,
        event.Result,
        event.PolicyName,
        event.EncryptionKey,
        event.Duration,
        fmt.Sprintf("File %s %s for user %s", event.Operation, event.Result, event.Username))
}
```

---

## Performance Optimization

### CPU Optimization

#### SIMD Acceleration

```c
// crypto_simd.c - SIMD-accelerated cryptographic operations
#include <immintrin.h>

// AES-NI accelerated encryption
static inline void aes_encrypt_block_ni(__m128i *block, const __m128i *round_keys, int rounds)
{
    *block = _mm_xor_si128(*block, round_keys[0]);
    
    for (int i = 1; i < rounds; i++) {
        *block = _mm_aesenc_si128(*block, round_keys[i]);
    }
    
    *block = _mm_aesenclast_si128(*block, round_keys[rounds]);
}

// Vectorized data processing
static void process_blocks_simd(uint8_t *data, size_t length, const uint8_t *key)
{
    const size_t block_size = 16;
    const size_t simd_width = 4; // Process 4 blocks at once
    const size_t simd_bytes = block_size * simd_width;
    
    __m128i round_keys[11];
    aes_key_schedule(key, round_keys);
    
    size_t i;
    for (i = 0; i + simd_bytes <= length; i += simd_bytes) {
        __m128i blocks[4];
        
        // Load 4 blocks
        blocks[0] = _mm_loadu_si128((__m128i*)(data + i));
        blocks[1] = _mm_loadu_si128((__m128i*)(data + i + block_size));
        blocks[2] = _mm_loadu_si128((__m128i*)(data + i + block_size * 2));
        blocks[3] = _mm_loadu_si128((__m128i*)(data + i + block_size * 3));
        
        // Encrypt 4 blocks in parallel
        aes_encrypt_block_ni(&blocks[0], round_keys, 10);
        aes_encrypt_block_ni(&blocks[1], round_keys, 10);
        aes_encrypt_block_ni(&blocks[2], round_keys, 10);
        aes_encrypt_block_ni(&blocks[3], round_keys, 10);
        
        // Store results
        _mm_storeu_si128((__m128i*)(data + i), blocks[0]);
        _mm_storeu_si128((__m128i*)(data + i + block_size), blocks[1]);
        _mm_storeu_si128((__m128i*)(data + i + block_size * 2), blocks[2]);
        _mm_storeu_si128((__m128i*)(data + i + block_size * 3), blocks[3]);
    }
    
    // Handle remaining blocks
    for (; i + block_size <= length; i += block_size) {
        __m128i block = _mm_loadu_si128((__m128i*)(data + i));
        aes_encrypt_block_ni(&block, round_keys, 10);
        _mm_storeu_si128((__m128i*)(data + i), block);
    }
}
```

#### Lock-Free Data Structures

```c
// lockfree_queue.c - Lock-free request queue
struct lockfree_queue {
    atomic_long head;
    atomic_long tail;
    struct queue_entry *entries;
    size_t mask;
};

struct queue_entry {
    atomic_long sequence;
    void *data;
};

static bool lockfree_queue_enqueue(struct lockfree_queue *queue, void *data)
{
    long tail, next_tail, sequence;
    struct queue_entry *entry;
    
    while (true) {
        tail = atomic_load(&queue->tail);
        entry = &queue->entries[tail & queue->mask];
        sequence = atomic_load(&entry->sequence);
        
        if (sequence == tail) {
            next_tail = tail + 1;
            if (atomic_compare_exchange_weak(&queue->tail, &tail, next_tail)) {
                entry->data = data;
                atomic_store(&entry->sequence, next_tail);
                return true;
            }
        } else if (sequence < tail) {
            return false; // Queue full
        }
        
        cpu_relax();
    }
}

static void *lockfree_queue_dequeue(struct lockfree_queue *queue)
{
    long head, next_head, sequence;
    struct queue_entry *entry;
    void *data;
    
    while (true) {
        head = atomic_load(&queue->head);
        entry = &queue->entries[head & queue->mask];
        sequence = atomic_load(&entry->sequence);
        
        if (sequence == head + 1) {
            next_head = head + 1;
            if (atomic_compare_exchange_weak(&queue->head, &head, next_head)) {
                data = entry->data;
                atomic_store(&entry->sequence, next_head + queue->mask);
                return data;
            }
        } else if (sequence < head + 1) {
            return NULL; // Queue empty
        }
        
        cpu_relax();
    }
}
```

### Memory Optimization

#### Memory Pool Management

```go
// pkg/memory/pool.go
package memory

import (
    "sync"
    "unsafe"
)

type MemoryPool struct {
    pools    []*sync.Pool
    sizes    []int
    maxSize  int
}

func NewMemoryPool(maxSize int) *MemoryPool {
    // Create pools for power-of-2 sizes
    var pools []*sync.Pool
    var sizes []int
    
    for size := 64; size <= maxSize; size *= 2 {
        size := size // Capture for closure
        pool := &sync.Pool{
            New: func() interface{} {
                return make([]byte, size)
            },
        }
        pools = append(pools, pool)
        sizes = append(sizes, size)
    }
    
    return &MemoryPool{
        pools:   pools,
        sizes:   sizes,
        maxSize: maxSize,
    }
}

func (mp *MemoryPool) Get(size int) []byte {
    // Find appropriate pool
    for i, poolSize := range mp.sizes {
        if size <= poolSize {
            buf := mp.pools[i].Get().([]byte)
            return buf[:size]
        }
    }
    
    // Size too large, allocate directly
    return make([]byte, size)
}

func (mp *MemoryPool) Put(buf []byte) {
    size := cap(buf)
    
    // Find appropriate pool
    for i, poolSize := range mp.sizes {
        if size == poolSize {
            // Clear buffer before returning to pool
            for j := range buf {
                buf[j] = 0
            }
            mp.pools[i].Put(buf[:poolSize])
            return
        }
    }
    
    // Not from pool, let GC handle it
}
```

#### Zero-Copy Optimization

```go
// pkg/netlink/zerocopy.go
package netlink

import (
    "syscall"
    "unsafe"
)

// Zero-copy message sending using sendmsg with scatter-gather
func (c *Client) SendMessageZeroCopy(header *MessageHeader, payload []byte) error {
    // Prepare header
    headerBytes := (*[unsafe.Sizeof(MessageHeader{})]byte)(unsafe.Pointer(header))
    
    // Prepare iovec for scatter-gather
    iov := []syscall.Iovec{
        {
            Base: &headerBytes[0],
            Len:  uint64(unsafe.Sizeof(MessageHeader{})),
        },
        {
            Base: &payload[0],
            Len:  uint64(len(payload)),
        },
    }
    
    // Prepare message
    msg := syscall.Msghdr{
        Name:    (*byte)(unsafe.Pointer(c.addr)),
        Namelen: uint32(unsafe.Sizeof(*c.addr)),
        Iov:     &iov[0],
        Iovlen:  uint64(len(iov)),
    }
    
    // Send using sendmsg for zero-copy
    _, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, 
                                  uintptr(c.socket), 
                                  uintptr(unsafe.Pointer(&msg)), 
                                  0)
    if errno != 0 {
        return errno
    }
    
    return nil
}
```

### I/O Optimization

#### Async I/O with io_uring

```go
// pkg/io/uring.go
package io

import (
    "github.com/iceber/iouring-go"
    "sync"
)

type AsyncIOManager struct {
    uring  *iouring.IOURing
    mu     sync.Mutex
    active map[uint64]*IORequest
}

type IORequest struct {
    ID       uint64
    File     *os.File
    Buffer   []byte
    Offset   int64
    Callback func([]byte, error)
}

func NewAsyncIOManager(queueDepth uint32) (*AsyncIOManager, error) {
    uring, err := iouring.New(queueDepth)
    if err != nil {
        return nil, err
    }
    
    mgr := &AsyncIOManager{
        uring:  uring,
        active: make(map[uint64]*IORequest),
    }
    
    go mgr.completionLoop()
    return mgr, nil
}

func (mgr *AsyncIOManager) ReadAsync(req *IORequest) error {
    mgr.mu.Lock()
    mgr.active[req.ID] = req
    mgr.mu.Unlock()
    
    // Submit read operation
    prepRequest := iouring.Pread(int(req.File.Fd()), req.Buffer, req.Offset)
    prepRequest.SetUserData(req.ID)
    
    if _, err := mgr.uring.SubmitRequest(prepRequest, nil); err != nil {
        mgr.mu.Lock()
        delete(mgr.active, req.ID)
        mgr.mu.Unlock()
        return err
    }
    
    return nil
}

func (mgr *AsyncIOManager) completionLoop() {
    for {
        cqe, err := mgr.uring.WaitCQEvent()
        if err != nil {
            continue
        }
        
        requestID := cqe.UserData()
        result := cqe.Result()
        
        mgr.mu.Lock()
        req, exists := mgr.active[requestID]
        if exists {
            delete(mgr.active, requestID)
        }
        mgr.mu.Unlock()
        
        if exists {
            if result < 0 {
                req.Callback(nil, syscall.Errno(-result))
            } else {
                req.Callback(req.Buffer[:result], nil)
            }
        }
        
        cqe.Done()
    }
}
```

---

## Error Handling and Recovery

### Graceful Error Handling

```go
// pkg/errors/handling.go
package errors

import (
    "context"
    "fmt"
    "time"
)

type ErrorHandler struct {
    logger    Logger
    metrics   MetricsCollector
    recovery  RecoveryManager
}

type RecoverableError interface {
    error
    IsRecoverable() bool
    RetryDelay() time.Duration
    MaxRetries() int
}

type CryptoError struct {
    message    string
    cause      error
    recoverable bool
    retryDelay time.Duration
}

func (e *CryptoError) Error() string {
    return fmt.Sprintf("crypto error: %s", e.message)
}

func (e *CryptoError) IsRecoverable() bool {
    return e.recoverable
}

func (e *CryptoError) RetryDelay() time.Duration {
    return e.retryDelay
}

func (e *CryptoError) MaxRetries() int {
    return 3
}

func (eh *ErrorHandler) HandleError(ctx context.Context, operation string, err error) error {
    // Log the error
    eh.logger.Error("Operation failed", "operation", operation, "error", err)
    
    // Update metrics
    eh.metrics.IncErrorCount(operation, err.Error())
    
    // Check if error is recoverable
    if recErr, ok := err.(RecoverableError); ok && recErr.IsRecoverable() {
        return eh.attemptRecovery(ctx, operation, recErr)
    }
    
    return err
}

func (eh *ErrorHandler) attemptRecovery(ctx context.Context, operation string, 
                                       err RecoverableError) error {
    maxRetries := err.MaxRetries()
    retryDelay := err.RetryDelay()
    
    for attempt := 1; attempt <= maxRetries; attempt++ {
        eh.logger.Info("Attempting recovery", 
                      "operation", operation, 
                      "attempt", attempt, 
                      "max_retries", maxRetries)
        
        // Wait before retry
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(retryDelay):
        }
        
        // Attempt recovery
        if recoveryErr := eh.recovery.Recover(operation); recoveryErr == nil {
            eh.logger.Info("Recovery successful", "operation", operation, "attempt", attempt)
            eh.metrics.IncRecoveryCount(operation, "success")
            return nil
        }
        
        // Exponential backoff
        retryDelay *= 2
    }
    
    eh.logger.Error("Recovery failed after all attempts", "operation", operation)
    eh.metrics.IncRecoveryCount(operation, "failed")
    return err
}
```

### Circuit Breaker Pattern

```go
// pkg/resilience/circuit_breaker.go
package resilience

import (
    "fmt"
    "sync"
    "time"
)

type CircuitBreaker struct {
    mu              sync.Mutex
    state           State
    failureCount    int
    successCount    int
    failureThreshold int
    successThreshold int
    timeout         time.Duration
    lastFailureTime time.Time
    onStateChange   func(State)
}

type State int

const (
    StateClosed State = iota
    StateOpen
    StateHalfOpen
)

func NewCircuitBreaker(failureThreshold, successThreshold int, timeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        state:           StateClosed,
        failureThreshold: failureThreshold,
        successThreshold: successThreshold,
        timeout:         timeout,
    }
}

func (cb *CircuitBreaker) Execute(operation func() error) error {
    cb.mu.Lock()
    
    // Check if we should transition from open to half-open
    if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.timeout {
        cb.setState(StateHalfOpen)
        cb.successCount = 0
    }
    
    // Reject if circuit is open
    if cb.state == StateOpen {
        cb.mu.Unlock()
        return fmt.Errorf("circuit breaker is open")
    }
    
    cb.mu.Unlock()
    
    // Execute operation
    err := operation()
    
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    if err != nil {
        cb.onFailure()
        return err
    }
    
    cb.onSuccess()
    return nil
}

func (cb *CircuitBreaker) onSuccess() {
    switch cb.state {
    case StateClosed:
        cb.failureCount = 0
    case StateHalfOpen:
        cb.successCount++
        if cb.successCount >= cb.successThreshold {
            cb.setState(StateClosed)
            cb.failureCount = 0
        }
    }
}

func (cb *CircuitBreaker) onFailure() {
    cb.failureCount++
    cb.lastFailureTime = time.Now()
    
    if cb.failureCount >= cb.failureThreshold {
        cb.setState(StateOpen)
    }
}

func (cb *CircuitBreaker) setState(state State) {
    if cb.state != state {
        cb.state = state
        if cb.onStateChange != nil {
            cb.onStateChange(state)
        }
    }
}
```

### Health Monitoring

```go
// pkg/health/monitor.go
package health

import (
    "context"
    "sync"
    "time"
)

type HealthMonitor struct {
    checks    map[string]HealthCheck
    results   map[string]*HealthResult
    mu        sync.RWMutex
    logger    Logger
    interval  time.Duration
}

type HealthCheck interface {
    Name() string
    Check(ctx context.Context) error
    Timeout() time.Duration
    Critical() bool
}

type HealthResult struct {
    Status    HealthStatus
    Message   string
    Timestamp time.Time
    Duration  time.Duration
    Error     error
}

type HealthStatus int

const (
    HealthStatusHealthy HealthStatus = iota
    HealthStatusDegraded
    HealthStatusUnhealthy
)

func (hm *HealthMonitor) Start(ctx context.Context) {
    ticker := time.NewTicker(hm.interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            hm.runHealthChecks(ctx)
        }
    }
}

func (hm *HealthMonitor) runHealthChecks(ctx context.Context) {
    var wg sync.WaitGroup
    
    for name, check := range hm.checks {
        wg.Add(1)
        go func(name string, check HealthCheck) {
            defer wg.Done()
            
            result := hm.executeHealthCheck(ctx, check)
            
            hm.mu.Lock()
            hm.results[name] = result
            hm.mu.Unlock()
            
            if result.Status != HealthStatusHealthy {
                hm.logger.Warn("Health check failed", 
                              "check", name, 
                              "status", result.Status,
                              "error", result.Error)
            }
        }(name, check)
    }
    
    wg.Wait()
}

func (hm *HealthMonitor) executeHealthCheck(ctx context.Context, check HealthCheck) *HealthResult {
    start := time.Now()
    
    checkCtx, cancel := context.WithTimeout(ctx, check.Timeout())
    defer cancel()
    
    err := check.Check(checkCtx)
    duration := time.Since(start)
    
    result := &HealthResult{
        Timestamp: start,
        Duration:  duration,
        Error:     err,
    }
    
    if err != nil {
        if check.Critical() {
            result.Status = HealthStatusUnhealthy
        } else {
            result.Status = HealthStatusDegraded
        }
        result.Message = err.Error()
    } else {
        result.Status = HealthStatusHealthy
        result.Message = "OK"
    }
    
    return result
}

// Kernel module health check
type KernelModuleHealthCheck struct {
    name string
}

func (k *KernelModuleHealthCheck) Name() string {
    return k.name
}

func (k *KernelModuleHealthCheck) Check(ctx context.Context) error {
    // Check if module is loaded
    if _, err := os.Stat("/proc/takakrypt/status"); os.IsNotExist(err) {
        return fmt.Errorf("kernel module not loaded")
    }
    
    // Read module status
    data, err := os.ReadFile("/proc/takakrypt/status")
    if err != nil {
        return fmt.Errorf("failed to read module status: %w", err)
    }
    
    // Parse status
    if !strings.Contains(string(data), "Active: Yes") {
        return fmt.Errorf("kernel module not active")
    }
    
    return nil
}

func (k *KernelModuleHealthCheck) Timeout() time.Duration {
    return 5 * time.Second
}

func (k *KernelModuleHealthCheck) Critical() bool {
    return true
}
```

---

*This technical implementation guide provides comprehensive details for understanding and working with the Takakrypt transparent encryption system. The implementation combines high-performance kernel-level interception with sophisticated userspace policy management to deliver enterprise-grade transparent encryption capabilities.*

*Document Version: 1.0*  
*Last Updated: 2025-07-27*  
*Implementation Status: Production Ready*