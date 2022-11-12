#!/usr/bin/env zsh

ifconfig tun-easyss create
ifconfig tun-easyss 198.18.0.1 198.18.0.1 up

route add -net 1.0.0.0/8 198.18.0.1
route add -net 2.0.0.0/7 198.18.0.1
route add -net 4.0.0.0/6 198.18.0.1
route add -net 8.0.0.0/5 198.18.0.1
route add -net 16.0.0.0/4 198.18.0.1
route add -net 32.0.0.0/3 198.18.0.1
route add -net 64.0.0.0/2 198.18.0.1
route add -net 128.0.0.0/1 198.18.0.1
route add -net 198.18.0.0/15 198.18.0.1

route add -net 43.129.235.177/32 192.168.3.1