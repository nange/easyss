#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
local_gateway=$4
tun_ip_sub_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

ip tuntap add mode tun dev "$tun_device"  # create tun device

ip addr add "$tun_ip_sub" dev "$tun_device"  # add ipv4 addr to device
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ip -6 addr add "$tun_ip_sub_v6" dev "$tun_device"  # add ipv6 addr to device
fi

ip link set dev "$tun_device" up  # enable tun device

ip route add default via "$tun_gw" dev "$tun_device" metric 1
ip route add "$local_gateway" via "$tun_gw" dev "$tun_device"

# add ipv6 ip route
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ip -6 route add default via "$tun_gw_v6" dev "$tun_device" metric 1
  ip -6 route add "$local_gateway_v6" via "$tun_gw_v6" dev "$tun_device"
fi
