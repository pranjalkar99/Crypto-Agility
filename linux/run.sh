#!/bin/bash

# TLS Analyzer Runner Script
# Simple wrapper for Kali_tls_capture

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/Kali_tls_capture"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Make binary executable if not already
if [ ! -x "$BINARY" ]; then
    chmod +x "$BINARY" 2>/dev/null
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}ERROR: Kali_tls_capture binary not found!${NC}"
    echo "Expected location: $BINARY"
    exit 1
fi

# Show help if no arguments
if [ $# -eq 0 ]; then
    echo -e "${BLUE}TLS Packet Analyzer for Kali Linux${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Quick Start:"
    echo "  $0 -L              # List network interfaces"
    echo "  $0 -I              # Interactive mode"
    echo "  $0 -r file.pcap    # Analyze PCAP file"
    echo "  $0 -f domains.txt  # Batch domain analysis"
    echo ""
    echo "Live Capture (requires sudo):"
    echo "  $0                 # Auto-select interface"
    echo "  $0 -i eth0         # Specific interface"
    echo "  $0 -l              # Local testing"
    echo ""
    echo "For full help: $0 -h"
    exit 0
fi

# Check if we need root privileges
NEEDS_ROOT=true

# These options don't need root
case "$1" in
    -r|-f|-h|--help)
        NEEDS_ROOT=false
        ;;
esac

# Request root if needed and not already root
if [ "$NEEDS_ROOT" = true ] && [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}TLS packet capture requires root privileges.${NC}"
    echo "Restarting with sudo..."
    exec sudo "$0" "$@"
fi

# Check dependencies quickly
check_deps() {
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo -e "${YELLOW}WARNING: tcpdump not found. Some features may not work.${NC}"
        echo "Install with: sudo apt install tcpdump libpcap-dev libssl-dev"
    fi
}

# Run dependency check for live capture
if [ "$NEEDS_ROOT" = true ]; then
    check_deps
fi

# Execute the TLS analyzer
exec "$BINARY" "$@"
