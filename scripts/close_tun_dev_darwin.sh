#!/bin/sh
tun_device=$1
tun_gw=$2
local_gateway=$4
tun_gw_v6=$5
server_ip_v6=$6
local_gateway_v6=$7

route delete -net 0.0.0.0/1 "$tun_gw"
route delete -net 128.0.0.0/1 "$tun_gw"

route delete -net "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then
  route delete -inet6 -net ::/1 -gateway "$tun_gw_v6"
  route delete -inet6 -net 8000::/1 -gateway "$tun_gw_v6"
  route delete -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi

ifconfig "$tun_device" down
ifconfig "$tun_device" delete
