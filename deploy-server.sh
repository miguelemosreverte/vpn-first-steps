#!/bin/bash

set -e

SERVER_IP="95.217.238.72"
SSH_KEY="~/.ssh/id_ed25519_hetzner"
REPO="https://github.com/miguelemosreverte/vpn-first-steps.git"
DEPLOY_DIR="/root/vpn-server"

echo "Deploying VPN server to $SERVER_IP..."

# SSH into server and deploy
ssh -i $SSH_KEY root@$SERVER_IP << 'ENDSSH'
set -e

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    rm go1.21.5.linux-amd64.tar.gz
fi

export PATH=$PATH:/usr/local/go/bin

# Clone or update repository
if [ -d "/root/vpn-first-steps" ]; then
    echo "Updating repository..."
    cd /root/vpn-first-steps
    git pull origin main
else
    echo "Cloning repository..."
    git clone https://github.com/miguelemosreverte/vpn-first-steps.git /root/vpn-first-steps
    cd /root/vpn-first-steps
fi

# Build server
echo "Building server..."
cd server
go build -o vpn-server main.go

# Stop existing server if running
pkill -f vpn-server || true

# Start server
echo "Starting VPN server..."
nohup ./vpn-server -port 8888 > /var/log/vpn-server.log 2>&1 &

echo "VPN server deployed and started!"
echo "View logs: tail -f /var/log/vpn-server.log"
ENDSSH

echo "Deployment complete!"
