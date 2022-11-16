#!/bin/sh
tun_device=$1
tun_ip=$2
tun_gw=$3
server_ip=$4
local_gateway=$5

#ifconfig utun9 create
ifconfig "$tun_device" "$tun_ip" "$tun_gw" up

route add -net 1.0.0.0/8 "$tun_gw"
route add -net 2.0.0.0/7 "$tun_gw"
route add -net 4.0.0.0/6 "$tun_gw"
route add -net 8.0.0.0/5 "$tun_gw"
route add -net 16.0.0.0/4 "$tun_gw"
route add -net 32.0.0.0/3 "$tun_gw"
route add -net 64.0.0.0/2 "$tun_gw"
route add -net 128.0.0.0/1 "$tun_gw"
route add -net 198.18.0.0/15 "$tun_gw"

route add -net "$server_ip" "$local_gateway"
route add "$local_gateway" "$tun_gw"