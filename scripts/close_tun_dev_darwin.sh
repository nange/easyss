#!/bin/sh
tun_device=$1
tun_gw=$2
server_ip=$3
local_gateway=$4
tun_gw_v6=$5
server_ip_v6=$6
local_gateway_v6=$7

route delete -net 1.0.0.0/8 "$tun_gw"
route delete -net 2.0.0.0/7 "$tun_gw"
route delete -net 4.0.0.0/6 "$tun_gw"
route delete -net 8.0.0.0/5 "$tun_gw"
route delete -net 16.0.0.0/4 "$tun_gw"
route delete -net 32.0.0.0/3 "$tun_gw"
route delete -net 64.0.0.0/2 "$tun_gw"
route delete -net 128.0.0.0/1 "$tun_gw"
route delete -net 198.18.0.0/15 "$tun_gw"

if [ -n "$server_ip" ]; then
  route delete -net "$server_ip" "$local_gateway"
fi
route delete -net "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then
  route delete -inet6 -net ::/0 -gateway "$tun_gw_v6"
  route delete -inet6 -net "$server_ip_v6" -gateway "$local_gateway_v6"
  route delete -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi

ifconfig "$tun_device" down
ifconfig "$tun_device" delete
