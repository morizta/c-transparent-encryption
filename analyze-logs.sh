#!/bin/bash

# Analyze all Takakrypt logs
LOG_DIR="/tmp"
ANALYSIS_DIR="/tmp/takakrypt-analysis-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$ANALYSIS_DIR"

echo "=== Takakrypt Log Analysis ===" | tee "$ANALYSIS_DIR/summary.txt"
echo "Generated at: $(date)" | tee -a "$ANALYSIS_DIR/summary.txt"
echo "" | tee -a "$ANALYSIS_DIR/summary.txt"

# Analyze kernel logs
if [ -f "$LOG_DIR/takakrypt-kernel-debug.log" ]; then
    echo "--- Kernel Module Analysis ---" | tee -a "$ANALYSIS_DIR/summary.txt"
    grep -c "VFS operation" "$LOG_DIR/takakrypt-kernel-debug.log" 2>/dev/null | tee -a "$ANALYSIS_DIR/summary.txt"
    grep -c "Policy evaluation" "$LOG_DIR/takakrypt-kernel-debug.log" 2>/dev/null | tee -a "$ANALYSIS_DIR/summary.txt"
    grep -c "Encryption" "$LOG_DIR/takakrypt-kernel-debug.log" 2>/dev/null | tee -a "$ANALYSIS_DIR/summary.txt"
fi

# Analyze agent logs
if [ -f "$LOG_DIR/takakrypt-agent-debug.log" ]; then
    echo "--- Agent Analysis ---" | tee -a "$ANALYSIS_DIR/summary.txt"
    grep -c "Processing request" "$LOG_DIR/takakrypt-agent-debug.log" 2>/dev/null | tee -a "$ANALYSIS_DIR/summary.txt"
    grep -c "Encryption operation" "$LOG_DIR/takakrypt-agent-debug.log" 2>/dev/null | tee -a "$ANALYSIS_DIR/summary.txt"
fi

# Create detailed reports
echo "Creating detailed analysis reports in: $ANALYSIS_DIR"

# Extract key events
grep "ERROR\|WARN\|encryption\|policy" "$LOG_DIR"/takakrypt-*.log 2>/dev/null > "$ANALYSIS_DIR/key-events.txt" || echo "No logs found"

echo "Analysis complete. Check: $ANALYSIS_DIR/summary.txt"
