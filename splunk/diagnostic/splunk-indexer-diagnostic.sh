#!/bin/bash
# Splunk Indexer Diagnostic Script
# Run on the Splunk indexer (Ubuntu/Linux host) to verify health,
# confirm logs are being received, and surface common issues.
#
# Usage: sudo bash splunk-indexer-diagnostic.sh

echo "========================================"
echo "Splunk Indexer Diagnostic Report"
echo "Host: $(hostname)"
echo "Date: $(date)"
echo "========================================"
echo ""

echo "=== SYSTEM RESOURCES (Disk & Memory) ==="
echo "Checking for disk space issues (critical for Indexers)..."
df -h
echo ""
echo "Checking memory usage..."
free -h
echo ""

echo "=== SPLUNK SERVICE STATUS ==="
if [ -f "/opt/splunk/bin/splunk" ]; then
    sudo /opt/splunk/bin/splunk status
else
    echo "Splunk binary not found at /opt/splunk/bin/splunk"
fi
echo ""

echo "=== SPLUNK PROCESS DETAILS ==="
ps aux | grep splunkd | head -n 10
echo ""

echo "=== LISTENING PORTS (Crucial for receiving logs) ==="
echo "Looking for Management (8089), Web (8000), and Indexing (9997)..."
sudo ss -tulpn | grep -E '8000|9997|8089'
echo ""

echo "=== FIREWALL STATUS (UFW) ==="
echo "Verifying ports are allowed through the OS firewall..."
sudo ufw status verbose
echo ""

echo "=== SPLUNK INPUTS.CONF (Listening Configuration) ==="
INPUTS_FILE="/opt/splunk/etc/system/default/inputs.conf"
if [ -f "$INPUTS_FILE" ]; then
    echo "Found inputs.conf at $INPUTS_FILE:"
    cat "$INPUTS_FILE"
else
    echo "No local inputs.conf found at $INPUTS_FILE (Check /etc/apps/ if using an app)"
fi
echo ""

echo "=== SPLUNKD.LOG (Last 50 Lines) ==="
LOG_FILE="/opt/splunk/var/log/splunk/splunkd.log"
if [ -f "$LOG_FILE" ]; then
    tail -n 50 "$LOG_FILE"
else
    echo "Log file not found at $LOG_FILE"
fi
echo ""

echo "=== INDEX STATUS (Bucket Directory) ==="
if [ -d "/opt/splunk/var/lib/splunk" ]; then
    ls -ld "/opt/splunk/var/lib/splunk"
    echo "Listing top level index directories..."
    ls -1 "/opt/splunk/var/lib/splunk" | head -n 10
else
    echo "Splunk data directory /opt/splunk/var/lib/splunk not found!"
fi
echo ""

echo "========================================"
echo "Diagnostic Complete"
echo "========================================"
