#!/bin/bash
tun_device=$1

# Flush the TUN routes before deleting the interface. Deleting the interface
# drops them too, but that delete fails with "device or resource busy" while a
# process still holds the TUN fd open (iproute2 attaches through TUNSETIFF, and
# the client closes its fd concurrently with this script), and the split routes
# then survive: every connection addressed to them enters an interface that
# nothing reads from, which looks like "the network is down" after stopping
# TUN. Best effort and silent when the interface is already gone.
ip route flush dev "$tun_device" >/dev/null 2>&1
ip -6 route flush dev "$tun_device" >/dev/null 2>&1

ip tuntap del mode tun dev "$tun_device"
