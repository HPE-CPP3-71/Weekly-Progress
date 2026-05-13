#!/bin/bash

INTERFACE="wlp0s20f3"
IP="192.168.0.1/20"

echo "[+] Stopping old services..."
sudo pkill dhcpd 2>/dev/null
sudo systemctl stop hostapd 2>/dev/null
sudo systemctl stop NetworkManager 2>/dev/null

echo "[+] Cleaning interface..."
sudo ip addr flush dev $INTERFACE

echo "[+] Setting interface IP..."
sudo ip addr add $IP dev $INTERFACE
sudo ip link set $INTERFACE up

echo "[+] Verifying interface..."
ip a show $INTERFACE

echo "[+] Resetting DHCP leases..."
sudo rm -f /var/lib/dhcpd/dhcpd.leases
sudo touch /var/lib/dhcpd/dhcpd.leases
sudo chown dhcpd:dhcpd /var/lib/dhcpd/dhcpd.leases

echo "[+] Starting hostapd..."
sudo systemctl restart hostapd

echo "[+] Starting DHCP server..."
sudo dhcpd -4 -cf /etc/dhcp/dhcpd.conf $INTERFACE

sleep 2

echo "[+] Checking DHCP status..."
if sudo ss -ulpn | grep -q ":67"; then
    echo "✅ DHCP SERVER RUNNING"
else
    echo "❌ DHCP FAILED TO START"
    exit 1
fi

echo ""
echo "=================================="
echo " DHCP LAB STARTED SUCCESSFULLY "
echo "=================================="
echo " Interface : $INTERFACE"
echo " Gateway   : 192.168.0.1"
echo " Network   : 192.168.0.0/20"
echo " DHCP Pool : 192.168.0.10 - 192.168.15.254"
echo "=================================="
