@echo off

set tun_device=%1
set tun_gw=%2

route delete 0.0.0.0 %tun_gw%

netsh interface ipv6 delete route ::/0 %tun_device%
