#!/bin/bash
echo "Installing dependencies for TLS Analyzer..."
sudo apt update
sudo apt install -y libpcap0.8 libssl3 libc6
echo "Dependencies installed!"
