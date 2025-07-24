package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
	"takakrypt/internal/kms"
	"takakrypt/internal/policy"
	"takakrypt/pkg/agent"
	"takakrypt/pkg/netlink"
)

var (
	configPath = flag.String("config", "/etc/takakrypt/config.yaml", "Path to configuration file")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	daemonize  = flag.Bool("daemon", false, "Run as daemon")
	pidFile    = flag.String("pid-file", "/var/run/takakrypt/agent.pid", "PID file path")
	version    = flag.Bool("version", false, "Show version and exit")
)

const (
	agentVersion = "1.0.0"
	agentName    = "takakrypt-agent"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s version %s\n", agentName, agentVersion)
		os.Exit(0)
	}

	// Setup logging
	if err := setupLogging(*logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup logging: %v\n", err)
		os.Exit(1)
	}

	logrus.WithFields(logrus.Fields{
		"version": agentVersion,
		"config":  *configPath,
	}).Info("Starting Takakrypt Transparent Encryption Agent")

	// Load configuration
	parser := config.NewParser(*configPath)
	cfg, err := parser.Load()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	logrus.WithFields(logrus.Fields{
		"guard_points": len(cfg.GuardPoints),
		"policies":     len(cfg.Policies),
		"user_sets":    len(cfg.UserSets),
		"process_sets": len(cfg.ProcessSets),
		"resource_sets": len(cfg.ResourceSets),
	}).Info("Configuration loaded successfully")

	// Create PID file if running as daemon
	if *daemonize {
		if err := createPIDFile(*pidFile); err != nil {
			logrus.WithError(err).Fatal("Failed to create PID file")
		}
		defer removePIDFile(*pidFile)
	}

	// Initialize components
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create encryption engine
	encEngine := crypto.NewEncryptionEngine()
	logrus.Info("Encryption engine initialized")

	// Create KMS client
	kmsClient := kms.NewMockKMSClient()
	if err := kmsClient.Configure(&cfg.KMS); err != nil {
		logrus.WithError(err).Fatal("Failed to configure KMS client")
	}
	logrus.Info("KMS client initialized")

	// Create policy engine
	policyEngine, err := policy.NewEngine(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create policy engine")
	}
	logrus.Info("Policy engine initialized")

	// Create netlink client for kernel communication
	netlinkClient, err := netlink.NewClient()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create netlink client")
	}
	logrus.Info("Netlink client initialized")

	// Create main agent
	agentConfig := &agent.Config{
		SocketPath:        cfg.Agent.SocketPath,
		LogLevel:          cfg.Agent.LogLevel,
		MaxCacheSize:      cfg.Agent.MaxCacheSize,
		CacheCleanupInterval: cfg.Agent.CacheCleanupInterval,
		WorkerThreads:     cfg.Agent.WorkerThreads,
		MaxRequestSize:    cfg.Agent.MaxRequestSize,
		RequestTimeout:    cfg.Agent.RequestTimeout,
		EnableMetrics:     cfg.Agent.EnableMetrics,
		MetricsPort:       cfg.Agent.MetricsPort,
	}

	mainAgent, err := agent.New(agentConfig, encEngine, kmsClient, policyEngine, netlinkClient)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create agent")
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start agent
	errChan := make(chan error, 1)
	go func() {
		if err := mainAgent.Start(ctx); err != nil {
			errChan <- fmt.Errorf("agent error: %w", err)
		}
	}()

	logrus.Info("Agent started successfully")

	// Main event loop
	for {
		select {
		case err := <-errChan:
			logrus.WithError(err).Error("Agent encountered error")
			cancel()
			return

		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				logrus.WithField("signal", sig).Info("Received shutdown signal")
				cancel()
				
				// Graceful shutdown with timeout
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer shutdownCancel()
				
				if err := mainAgent.Stop(shutdownCtx); err != nil {
					logrus.WithError(err).Error("Error during shutdown")
				}
				
				logrus.Info("Agent shutdown complete")
				return

			case syscall.SIGHUP:
				logrus.Info("Received SIGHUP, reloading configuration")
				if err := reloadConfiguration(parser, cfg, policyEngine); err != nil {
					logrus.WithError(err).Error("Failed to reload configuration")
				}
			}

		case <-ctx.Done():
			logrus.Info("Context cancelled, shutting down")
			return
		}
	}
}

// setupLogging configures the logging system
func setupLogging(level string) error {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: false,
	})

	parsedLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", level, err)
	}

	logrus.SetLevel(parsedLevel)
	return nil
}

// createPIDFile creates a PID file for daemon mode
func createPIDFile(pidPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(pidPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	// Check if PID file already exists
	if _, err := os.Stat(pidPath); err == nil {
		return fmt.Errorf("PID file %s already exists", pidPath)
	}

	// Create PID file
	pidFile, err := os.Create(pidPath)
	if err != nil {
		return fmt.Errorf("failed to create PID file: %w", err)
	}
	defer pidFile.Close()

	if _, err := fmt.Fprintf(pidFile, "%d\n", os.Getpid()); err != nil {
		return fmt.Errorf("failed to write PID: %w", err)
	}

	return nil
}

// removePIDFile removes the PID file
func removePIDFile(pidPath string) {
	if err := os.Remove(pidPath); err != nil {
		logrus.WithError(err).Warn("Failed to remove PID file")
	}
}

// reloadConfiguration reloads the configuration and updates components
func reloadConfiguration(parser *config.Parser, cfg *config.Config, policyEngine *policy.Engine) error {
	logrus.Info("Reloading configuration")

	newCfg, err := parser.Reload()
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	// Update policy engine
	if err := policyEngine.UpdateConfiguration(newCfg); err != nil {
		return fmt.Errorf("failed to update policy engine: %w", err)
	}

	// Update global config reference
	*cfg = *newCfg

	logrus.WithFields(logrus.Fields{
		"guard_points": len(newCfg.GuardPoints),
		"policies":     len(newCfg.Policies),
		"user_sets":    len(newCfg.UserSets),
		"process_sets": len(newCfg.ProcessSets),
		"resource_sets": len(newCfg.ResourceSets),
	}).Info("Configuration reloaded successfully")

	return nil
}