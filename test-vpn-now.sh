#!/bin/bash
echo "osopanda" | sudo -S ./client/vpn-client -server 95.217.238.72:8888 > /tmp/vpn-test-now.log 2>&1 &
VPN_PID=$!
sleep 10
cat /tmp/vpn-test-now.log
echo ""
echo "=== VPN Process ==="
ps aux | grep "[v]pn-client" | head -2
echo ""
echo "=== My IP (should be 95.217.238.72) ==="
curl -s --max-time 10 ifconfig.me
echo ""
echo "osopanda" | sudo -S kill $VPN_PID 2>/dev/null
sleep 2
