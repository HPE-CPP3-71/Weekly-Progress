#!/bin/bash

INTERFACE="wlp0s20f3"

echo "[+] Stopping DHCP server..."
sudo pkill dhcpd 2>/dev/null

echo "[+] Stopping Access Point..."
sudo systemctl stop hostapd 2>/dev/null

echo "[+] Cleaning interface..."
sudo ip addr flush dev $INTERFACE

echo "[+] Restoring NetworkManager..."
sudo systemctl start NetworkManager
sudo systemctl enable NetworkManager

echo "[+] Restoring WiFi managed mode..."
nmcli device set $INTERFACE managed yes

echo "[+] Restarting WiFi..."
nmcli radio wifi off
sleep 2
nmcli radio wifi on

sleep 3

echo "[+] Rescanning WiFi networks..."
nmcli device wifi rescan

echo ""
echo "=================================="
echo " DHCP LAB STOPPED "
echo " WiFi restored successfully "
echo "=================================="
