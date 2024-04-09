echo "Please wait a moment... This window will be closed after the operation completed"
@echo off

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set server_ip=%5
set local_gateway=%6
set tun_ip_v6=%7
set tun_gw_v6=%8
set server_ip_v6=%9
set local_gateway_v6=%10

netsh interface ip set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw%
netsh interface ip set dns name=%tun_device% static 8.8.8.8

if not "%server_ip_v6%"=="" (
    netsh interface ipv6 add address %tun_device% %tun_ip_v6%
    netsh interface ipv6 add route ::/0 %tun_device% %tun_ip_v6%
)

if not "%server_ip%"=="" (
    route add %server_ip% %local_gateway% metric 5
)
route add 0.0.0.0 mask 0.0.0.0 %tun_gw% metric 5

