#!/bin/sh
tun_gw=$1
server_ip=$2
local_gateway=$3

route delete -net 1.0.0.0/8 "$tun_gw"
route delete -net 2.0.0.0/7 "$tun_gw"
route delete -net 4.0.0.0/6 "$tun_gw"
route delete -net 8.0.0.0/5 "$tun_gw"
route delete -net 16.0.0.0/4 "$tun_gw"
route delete -net 32.0.0.0/3 "$tun_gw"
route delete -net 64.0.0.0/2 "$tun_gw"
route delete -net 128.0.0.0/1 "$tun_gw"
route delete -net 198.18.0.0/15 "$tun_gw"

route delete -net "$server_ip" "$local_gateway"
