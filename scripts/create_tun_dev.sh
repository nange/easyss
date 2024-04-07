#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
server_ip=$4
local_gateway=$5
local_device=$6
tun_ip_sub_v6=$7
tun_gw_v6='fe80::30ff:1eff:feff:aaff'
server_ip_v6=$9
local_gateway_v6=${10}
local_device_v6=${11}

ip tuntap add mode tun dev "$tun_device"  # add tun device

ip addr add "$tun_ip_sub" dev "$tun_device"  # add ipv4 addr to device
ip -6 addr add "$tun_ip_sub_v6" dev "$tun_device"  # add ipv6 addr to device

ip link set dev "$tun_device" up  # enable tun device

# add ipv4 ip route
if [ -n "$server_ip" ]; then  # check if server_ip is not empty
  ip route add "$server_ip" via "$local_gateway" dev "$local_device"
  ip route add default via "$tun_gw" dev "$tun_device" metric 1
  ip route add "$local_gateway" via "$tun_gw" dev "$tun_device"
fi

# add ipv6 ip route
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ip -6 route add "$server_ip_v6" via "$local_gateway_v6" dev "$local_device_v6"
  ip -6 route add default via "$tun_gw_v6" dev "$tun_device" metric 1
  ip -6 route add "$local_gateway_v6" via "$tun_gw_v6" dev "$tun_device"
fi
