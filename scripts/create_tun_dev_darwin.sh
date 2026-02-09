#!/bin/sh
tun_device=$1
tun_ip=$2
tun_gw=$3
local_gateway=$4
tun_ip_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# create tun device
ifconfig "$tun_device" "$tun_ip" "$tun_gw" up
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  ifconfig "$tun_device" inet6 "$tun_ip_v6"/64  up
fi

# add ipv4 ip route
route add -net 0.0.0.0/1 "$tun_gw"
route add -net 128.0.0.0/1 "$tun_gw"


if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  # add ipv6 ip route
  route add -inet6 -net ::/1 -gateway "$tun_gw_v6"
  route add -inet6 -net 8000::/1 -gateway "$tun_gw_v6"
fi
