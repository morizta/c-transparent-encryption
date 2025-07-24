package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"takakrypt/internal/crypto"
	"takakrypt/internal/kms"
	"takakrypt/internal/policy"
	"takakrypt/pkg/netlink"
)

// Config contains configuration for the agent
type Config struct {
	SocketPath           string
	LogLevel             string
	MaxCacheSize         int
	CacheCleanupInterval time.Duration
	WorkerThreads        int
	MaxRequestSize       int64
	RequestTimeout       time.Duration
	EnableMetrics        bool
	MetricsPort          int
}

// Agent represents the main transparent encryption agent
type Agent struct {
	config        *Config
	encEngine     *crypto.EncryptionEngine
	kmsClient     kms.KMSClient
	policyEngine  *policy.Engine
	netlinkClient *netlink.Client

	// Runtime state
	running    bool
	mu         sync.RWMutex
	workers    []*Worker
	stopChan   chan struct{}
	doneChan   chan struct{}

	// Statistics
	stats *Statistics
}

// Statistics contains runtime statistics
type Statistics struct {
	mu                   sync.RWMutex
	StartTime            time.Time
	RequestsProcessed    uint64
	RequestsSuccessful   uint64
	RequestsFailed       uint64
	PolicyChecks         uint64
	EncryptionOps        uint64
	DecryptionOps        uint64
	CacheHits            uint64
	CacheMisses          uint64
	KMSRequests          uint64
	KMSErrors            uint64
	ActiveWorkers        int
	AverageResponseTime  time.Duration
	LastActivityTime     time.Time
}

// Worker represents a worker goroutine for processing requests
type Worker struct {
	id     int
	agent  *Agent
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new agent instance
func New(config *Config, encEngine *crypto.EncryptionEngine, kmsClient kms.KMSClient,
	policyEngine *policy.Engine, netlinkClient *netlink.Client) (*Agent, error) {

	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	agent := &Agent{
		config:        config,
		encEngine:     encEngine,
		kmsClient:     kmsClient,
		policyEngine:  policyEngine,
		netlinkClient: netlinkClient,
		stopChan:      make(chan struct{}),
		doneChan:      make(chan struct{}),
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}

	return agent, nil
}

// Start starts the agent and all its components
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return fmt.Errorf("agent is already running")
	}

	logrus.Info("Starting transparent encryption agent")

	// Start netlink client
	if err := a.netlinkClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect netlink client: %w", err)
	}

	// Start workers
	if err := a.startWorkers(ctx); err != nil {
		return fmt.Errorf("failed to start workers: %w", err)
	}

	// Start metrics server if enabled
	if a.config.EnableMetrics {
		if err := a.startMetricsServer(ctx); err != nil {
			logrus.WithError(err).Warn("Failed to start metrics server")
		}
	}

	// Start background tasks
	go a.backgroundTasks(ctx)

	a.running = true
	a.stats.mu.Lock()
	a.stats.LastActivityTime = time.Now()
	a.stats.mu.Unlock()

	logrus.WithFields(logrus.Fields{
		"workers":      len(a.workers),
		"metrics_port": a.config.MetricsPort,
	}).Info("Agent started successfully")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logrus.Info("Agent context cancelled")
	case <-a.stopChan:
		logrus.Info("Agent stop signal received")
	}

	return nil
}

// Stop stops the agent gracefully
func (a *Agent) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	logrus.Info("Stopping transparent encryption agent")

	// Signal stop to all components
	close(a.stopChan)

	// Stop workers
	a.stopWorkers()

	// Disconnect netlink client
	if err := a.netlinkClient.Disconnect(); err != nil {
		logrus.WithError(err).Warn("Error disconnecting netlink client")
	}

	// Close KMS client
	if err := a.kmsClient.Close(); err != nil {
		logrus.WithError(err).Warn("Error closing KMS client")
	}

	// Clear encryption engine cache
	a.encEngine.ClearCache()

	a.running = false

	// Wait for background tasks to complete (with timeout)
	select {
	case <-a.doneChan:
		logrus.Info("Agent stopped gracefully")
	case <-ctx.Done():
		logrus.Warn("Agent stop timed out")
	}

	return nil
}

// startWorkers starts the worker goroutines
func (a *Agent) startWorkers(ctx context.Context) error {
	workerCount := a.config.WorkerThreads
	if workerCount <= 0 {
		workerCount = 4
	}

	a.workers = make([]*Worker, workerCount)

	for i := 0; i < workerCount; i++ {
		workerCtx, cancel := context.WithCancel(ctx)
		worker := &Worker{
			id:     i + 1,
			agent:  a,
			ctx:    workerCtx,
			cancel: cancel,
		}

		a.workers[i] = worker
		go worker.run()
	}

	a.stats.mu.Lock()
	a.stats.ActiveWorkers = workerCount
	a.stats.mu.Unlock()

	logrus.WithField("worker_count", workerCount).Info("Started worker goroutines")
	return nil
}

// stopWorkers stops all worker goroutines
func (a *Agent) stopWorkers() {
	logrus.Info("Stopping worker goroutines")

	for _, worker := range a.workers {
		if worker.cancel != nil {
			worker.cancel()
		}
	}

	// Wait for workers to finish (with timeout)
	timeout := time.After(10 * time.Second)
	for _, worker := range a.workers {
		select {
		case <-worker.ctx.Done():
			continue
		case <-timeout:
			logrus.Warn("Worker shutdown timed out")
			break
		}
	}

	a.stats.mu.Lock()
	a.stats.ActiveWorkers = 0
	a.stats.mu.Unlock()

	logrus.Info("All workers stopped")
}

// backgroundTasks runs background maintenance tasks
func (a *Agent) backgroundTasks(ctx context.Context) {
	defer close(a.doneChan)

	// Cache cleanup ticker
	cacheCleanupTicker := time.NewTicker(a.config.CacheCleanupInterval)
	defer cacheCleanupTicker.Stop()

	// Health check ticker
	healthCheckTicker := time.NewTicker(30 * time.Second)
	defer healthCheckTicker.Stop()

	// Statistics update ticker
	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	logrus.Info("Background tasks started")

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Background tasks shutting down")
			return

		case <-a.stopChan:
			logrus.Info("Background tasks received stop signal")
			return

		case <-cacheCleanupTicker.C:
			a.performCacheCleanup()

		case <-healthCheckTicker.C:
			a.performHealthCheck(ctx)

		case <-statsTicker.C:
			a.logStatistics()
		}
	}
}

// performCacheCleanup performs periodic cache cleanup
func (a *Agent) performCacheCleanup() {
	logrus.Debug("Performing cache cleanup")

	// TODO: Implement cache cleanup for policy decisions
	// This would clean up expired cache entries in the policy engine

	logrus.Debug("Cache cleanup completed")
}

// performHealthCheck performs periodic health checks
func (a *Agent) performHealthCheck(ctx context.Context) {
	logrus.Debug("Performing health check")

	// Check KMS connectivity
	if err := a.kmsClient.HealthCheck(ctx); err != nil {
		logrus.WithError(err).Warn("KMS health check failed")
		a.stats.mu.Lock()
		a.stats.KMSErrors++
		a.stats.mu.Unlock()
	}

	// Check netlink connectivity
	if !a.netlinkClient.IsConnected() {
		logrus.Warn("Netlink client is not connected")
		// Attempt reconnection
		if err := a.netlinkClient.Connect(ctx); err != nil {
			logrus.WithError(err).Error("Failed to reconnect netlink client")
		}
	}

	logrus.Debug("Health check completed")
}

// logStatistics logs current runtime statistics
func (a *Agent) logStatistics() {
	stats := a.GetStatistics()

	logrus.WithFields(logrus.Fields{
		"uptime_seconds":       int(time.Since(stats.StartTime).Seconds()),
		"requests_processed":   stats.RequestsProcessed,
		"requests_successful":  stats.RequestsSuccessful,
		"requests_failed":      stats.RequestsFailed,
		"policy_checks":        stats.PolicyChecks,
		"encryption_ops":       stats.EncryptionOps,
		"decryption_ops":       stats.DecryptionOps,
		"cache_hits":           stats.CacheHits,
		"cache_misses":         stats.CacheMisses,
		"kms_requests":         stats.KMSRequests,
		"kms_errors":           stats.KMSErrors,
		"active_workers":       stats.ActiveWorkers,
		"avg_response_time_ms": float64(stats.AverageResponseTime.Nanoseconds()) / 1000000,
	}).Info("Agent runtime statistics")
}

// startMetricsServer starts the metrics HTTP server
func (a *Agent) startMetricsServer(ctx context.Context) error {
	// TODO: Implement Prometheus metrics server
	logrus.WithField("port", a.config.MetricsPort).Info("Metrics server would start here")
	return nil
}

// GetStatistics returns a copy of current statistics
func (a *Agent) GetStatistics() *Statistics {
	a.stats.mu.RLock()
	defer a.stats.mu.RUnlock()

	// Return a copy to avoid race conditions
	return &Statistics{
		StartTime:           a.stats.StartTime,
		RequestsProcessed:   a.stats.RequestsProcessed,
		RequestsSuccessful:  a.stats.RequestsSuccessful,
		RequestsFailed:      a.stats.RequestsFailed,
		PolicyChecks:        a.stats.PolicyChecks,
		EncryptionOps:       a.stats.EncryptionOps,
		DecryptionOps:       a.stats.DecryptionOps,
		CacheHits:           a.stats.CacheHits,
		CacheMisses:         a.stats.CacheMisses,
		KMSRequests:         a.stats.KMSRequests,
		KMSErrors:           a.stats.KMSErrors,
		ActiveWorkers:       a.stats.ActiveWorkers,
		AverageResponseTime: a.stats.AverageResponseTime,
		LastActivityTime:    a.stats.LastActivityTime,
	}
}

// IsRunning returns whether the agent is currently running
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// run is the main worker loop
func (w *Worker) run() {
	logrus.WithField("worker_id", w.id).Info("Worker started")

	defer func() {
		logrus.WithField("worker_id", w.id).Info("Worker stopped")
	}()

	for {
		select {
		case <-w.ctx.Done():
			return

		default:
			// Process requests from netlink
			if err := w.processRequests(); err != nil {
				logrus.WithFields(logrus.Fields{
					"worker_id": w.id,
					"error":     err,
				}).Error("Error processing requests")

				// Brief pause on error to avoid tight loop
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// processRequests handles incoming requests from the kernel module
func (w *Worker) processRequests() error {
	// TODO: Implement actual request processing
	// This would:
	// 1. Receive requests from netlink client
	// 2. Process policy checks, encryption/decryption
	// 3. Send responses back to kernel

	logrus.WithField("worker_id", w.id).Debug("Processing requests (placeholder)")

	// Simulate work
	time.Sleep(100 * time.Millisecond)

	return nil
}