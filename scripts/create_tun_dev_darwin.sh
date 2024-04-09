#!/bin/sh
tun_device=$1
tun_ip=$2
tun_gw=$3
server_ip=$4
local_gateway=$5
tun_ip_v6=$6
tun_gw_v6=$7
server_ip_v6=$8
local_gateway_v6=$9

# create tun device
ifconfig "$tun_device" "$tun_ip" "$tun_gw" up
ifconfig "$tun_device" inet6 "$tun_ip_v6" "$tun_gw_v6" up

# add ipv4 ip route
route add -net 1.0.0.0/8 "$tun_gw"
route add -net 2.0.0.0/7 "$tun_gw"
route add -net 4.0.0.0/6 "$tun_gw"
route add -net 8.0.0.0/5 "$tun_gw"
route add -net 16.0.0.0/4 "$tun_gw"
route add -net 32.0.0.0/3 "$tun_gw"
route add -net 64.0.0.0/2 "$tun_gw"
route add -net 128.0.0.0/1 "$tun_gw"
route add -net 198.18.0.0/15 "$tun_gw"

if [ -n "$server_ip" ]; then  # check if server_ip is not empty
  route add -net "$server_ip" "$local_gateway"
fi
route add "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  # add ipv6 ip route
  route add -inet6 -net ::/0 -gateway "$tun_gw_v6"
  route add -inet6 -net "$server_ip_v6" -gateway "$local_gateway_v6"
  route add -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi
