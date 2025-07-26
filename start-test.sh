#!/bin/bash

# Quick test startup script for Takakrypt

echo "Starting Takakrypt agent with test configuration..."
echo "Press Ctrl+C to stop"
echo ""

# Start the agent
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml