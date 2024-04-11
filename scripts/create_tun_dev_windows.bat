echo "Please wait a moment... This window will be closed after the operation completed"
@echo off

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set tun_ip_sub_v6=%5
set tun_gw_v6=%6
set server_ip_v6=%7

netsh interface ip set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw%
netsh interface ip set dns name=%tun_device% static 8.8.8.8

route add 0.0.0.0 mask 0.0.0.0 %tun_gw% metric 5

if not "%server_ip_v6%"=="" (
    netsh interface ipv6 add address %tun_device% %tun_ip_sub_v6%
    netsh interface ipv6 set route %tun_device% ::/0 %tun_gw_v6%

    netsh interface ipv6 set interface %tun_device% forwarding=enabled
    netsh interface ipv6 add route ::/0 %tun_device% metric=1
)
