@echo off

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set server_ip=%5
set local_gateway=%6

netsh interface ip set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw%
netsh interface ip set dns name=%tun_device% static 8.8.8.8

route add %server_ip% %local_gateway% metric 5
route add 0.0.0.0 mask 0.0.0.0 %tun_gw% metric 5
