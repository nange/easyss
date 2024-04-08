#!/bin/bash
tun_device=$1
server_ip=$2
local_gateway=$3
local_device=$4
server_ip_v6=$5
local_gateway_v6=$6
local_device_v6=$7

ip tuntap del mode tun dev "$tun_device"

if [ -n "$server_ip" ]; then
  ip route del "$server_ip" via "$local_gateway" dev "$local_device"
fi

if [ -n "$server_ip_v6" ]; then
  ip -6 route del "$server_ip_v6" via "$local_gateway_v6" dev "$local_device_v6"
fi
