#!/bin/bash
tun_device=$1
server_ip=$2
local_gateway=$3
local_device=$4

ip tuntap add mode tun dev "$tun_device"
ip addr add 198.18.0.1/15 dev "$tun_device"
ip link set dev "$tun_device" up

ip route add "$server_ip" via "$local_gateway" dev "$local_device"
ip route add default via 198.18.0.1 dev "$tun_device" metric 1
