#!/bin/bash

set -e

echo "Building VPN client..."

cd client
go build -o vpn-client main.go

echo "Build complete! Binary: client/vpn-client"
echo ""
echo "Usage:"
echo "  # Without encryption (development mode)"
echo "  sudo ./client/vpn-client -server 95.217.238.72:8888"
echo ""
echo "  # With encryption"
echo "  sudo ./client/vpn-client -server 95.217.238.72:8888 -encrypt"
echo ""
echo "The client will automatically:"
echo "  - Connect to the VPN server"
echo "  - Route all traffic through the VPN"
echo "  - Use encryption if -encrypt flag is set"
echo ""
echo "Press Ctrl+C to disconnect and restore normal routing"
