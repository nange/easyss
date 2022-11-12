#!/bin/bash
tun_device=$1
server_ip=$2
local_gateway=$3
local_device=$4

ip tuntap del mode tun dev "$tun_device"
ip route del "$server_ip" via "$local_gateway" dev "$local_device"
