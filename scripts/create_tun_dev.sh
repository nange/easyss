#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
server_ip=$4
local_gateway=$5
local_device=$6
tun_ip_sub_v6=$7
local_gateway_v6=$8
local_device_v6=$9

ip tuntap add mode tun dev "$tun_device"
ip addr add "$tun_ip_sub" dev "$tun_device"
ip -6 addr add "$tun_ip_sub_v6" dev "$tun_device"
ip link set dev "$tun_device" up

ip route add "$server_ip" via "$local_gateway" dev "$local_device"
ip route add default via "$tun_gw" dev "$tun_device" metric 1
ip route add "$local_gateway" via "$tun_gw" dev "$tun_device"

ip -6 route add