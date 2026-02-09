@echo off

set tun_device=%1
set tun_gw=%2

route delete 0.0.0.0 mask 128.0.0.0 %tun_gw%
route delete 128.0.0.0 mask 128.0.0.0 %tun_gw%

netsh interface ipv6 delete route ::/1 %tun_device%
netsh interface ipv6 delete route 8000::/1 %tun_device%
