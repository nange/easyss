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

rem Route everything except 0.0.0.0/8 through the TUN device, mirroring the
rem darwin script. 0.0.0.1 (used to probe the physical default interface)
rem must stay outside the TUN routes.
route add 1.0.0.0 mask 254.0.0.0 %tun_gw% metric 5
route add 4.0.0.0 mask 252.0.0.0 %tun_gw% metric 5
route add 8.0.0.0 mask 248.0.0.0 %tun_gw% metric 5
route add 16.0.0.0 mask 240.0.0.0 %tun_gw% metric 5
route add 32.0.0.0 mask 224.0.0.0 %tun_gw% metric 5
route add 64.0.0.0 mask 192.0.0.0 %tun_gw% metric 5
route add 128.0.0.0 mask 128.0.0.0 %tun_gw% metric 5

if not "%server_ip_v6%"=="" (
    netsh interface ipv6 add address %tun_device% %tun_ip_sub_v6%
    netsh interface ipv6 set interface %tun_device% forwarding=enabled
    netsh interface ipv6 add route ::/1 %tun_device% metric=1
    netsh interface ipv6 add route 8000::/1 %tun_device% metric=1
)
