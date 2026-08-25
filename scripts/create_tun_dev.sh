#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
local_gateway=$4
tun_ip_sub_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

ip addr add "$tun_ip_sub" dev "$tun_device"  # add ipv4 addr to device
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ip -6 addr add "$tun_ip_sub_v6" dev "$tun_device"  # add ipv6 addr to device
fi

ip link set dev "$tun_device" up  # enable tun device

# Route everything except 0.0.0.0/8 through the TUN device, mirroring the
# darwin script. 0.0.0.1 (used to probe the physical default interface)
# must stay outside the TUN routes.
ip route add 1.0.0.0/7 via "$tun_gw" dev "$tun_device"
ip route add 4.0.0.0/6 via "$tun_gw" dev "$tun_device"
ip route add 8.0.0.0/5 via "$tun_gw" dev "$tun_device"
ip route add 16.0.0.0/4 via "$tun_gw" dev "$tun_device"
ip route add 32.0.0.0/3 via "$tun_gw" dev "$tun_device"
ip route add 64.0.0.0/2 via "$tun_gw" dev "$tun_device"
ip route add 128.0.0.0/1 via "$tun_gw" dev "$tun_device"
ip route add "$local_gateway" via "$tun_gw" dev "$tun_device"

# add ipv6 ip route
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ip -6 route add ::/1 via "$tun_gw_v6" dev "$tun_device"
  ip -6 route add 8000::/1 via "$tun_gw_v6" dev "$tun_device"
  if [ -n "$local_gateway_v6" ]; then
    ip -6 route add "$local_gateway_v6" via "$tun_gw_v6" dev "$tun_device"
  fi
fi
