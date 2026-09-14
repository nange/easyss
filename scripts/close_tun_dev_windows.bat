@echo off

set tun_device=%1
set tun_gw=%2
set tun_ip_v6=%3

rem Best-effort cleanup: a delete may legitimately fail (the object is
rem already gone) and the caller only logs the outcome. "call" keeps the
rem script running when a tool on PATH is a .bat/.cmd that fails, so one
rem failing delete cannot skip the rest.
call route delete 1.0.0.0 mask 255.0.0.0 %tun_gw%
call route delete 2.0.0.0 mask 254.0.0.0 %tun_gw%
call route delete 4.0.0.0 mask 252.0.0.0 %tun_gw%
call route delete 8.0.0.0 mask 248.0.0.0 %tun_gw%
call route delete 16.0.0.0 mask 240.0.0.0 %tun_gw%
call route delete 32.0.0.0 mask 224.0.0.0 %tun_gw%
call route delete 64.0.0.0 mask 192.0.0.0 %tun_gw%
call route delete 128.0.0.0 mask 128.0.0.0 %tun_gw%

call netsh interface ipv6 delete route ::/1 %tun_device%
call netsh interface ipv6 delete route 8000::/1 %tun_device%

rem netsh add address is persistent and the create script's "add address"
rem refuses to duplicate it, so the v6 address has to be removed here for
rem the next start (and for the rollback of a failed create) to succeed.
rem The third argument is the bare address without the /prefix, which is
rem what "netsh delete address" takes.
if not "%tun_ip_v6%"=="" call netsh interface ipv6 delete address %tun_device% %tun_ip_v6%
