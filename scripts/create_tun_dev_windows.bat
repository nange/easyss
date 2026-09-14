echo "Please wait a moment... This window will be closed after the operation completed"
@echo off

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set tun_ip_sub_v6=%5
set tun_gw_v6=%6
set server_ip_v6=%7

rem Exit code contract: the caller (client/tun/tun.go) keeps the TUN routes
rem installed only when this script exits 0. cmd.exe returns 0 for a batch file
rem with no explicit "exit /b" even when the commands inside it failed, so
rem every command below is followed by an "if errorlevel 1" guard that records
rem the failure and the script always ends with "exit /b 0" / "exit /b 1".
rem Dropping either half silently turns a failed configuration into a
rem successful start, after which all traffic is routed into a device that has
rem no address and no DNS (traffic loop).
rem
rem No command runs inside an "if (...) else (...)" block, and every command is
rem prefixed with "call": without it cmd.exe ends the whole script right there
rem with that command's exit code as soon as the command fails, skipping every
rem guard that follows (a batch-file tool on PATH is enough to trigger it).
rem %ERRORLEVEL% is never expanded next to the command it belongs to
rem ("cmd || exit /b %ERRORLEVEL%" would expand before the command runs);
rem "if errorlevel 1" is used instead.
set FAIL=

rem Re-applying an already configured address is a no-op that netsh reports as
rem an error ("already exists"), and this script runs on every TUN start while
rem the adapter keeps its address. Skipping such a command is what makes the
rem script idempotent; failing on it would break every start after the first.
rem "findstr /C:" matches the transport string (fields are localized: "IP
rem Address" on English Windows, "IP 地址" on Chinese), and the surrounding
rem spaces keep 198.18.0.1 from matching a longer address such as 198.18.0.11.
rem The query commands are read-only, so a failed query (device missing, no
rem permission) simply takes the "apply the setting" branch below.
call netsh interface ipv4 show addresses %tun_device% | findstr /C:" %tun_ip% " >nul 2>&1
if not errorlevel 1 (
    echo [create_tun_dev_windows] address %tun_ip% already set on %tun_device%, skipped
    goto have_addr
)
call netsh interface ipv4 set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw%
if errorlevel 1 set FAIL=address
:have_addr

call netsh interface ipv4 show dnsservers %tun_device% | findstr /C:"8.8.8.8" >nul 2>&1
if not errorlevel 1 (
    echo [create_tun_dev_windows] dns 8.8.8.8 already set on %tun_device%, skipped
    goto have_dns
)
call netsh interface ipv4 set dns name=%tun_device% static 8.8.8.8
if errorlevel 1 set FAIL=dns
:have_dns

rem Route everything except 0.0.0.0/8 through the TUN device, mirroring the
rem darwin script. 0.0.0.1 (used to probe the physical default interface)
rem must stay outside the TUN routes.
rem
rem The blocks below must form one contiguous ladder from 1.0.0.0 up to
rem 255.255.255.255 (1.0.0.0/8 + 2.0.0.0/7 + 4.0.0.0/6 + ... + 128.0.0.0/1):
rem a skipped block leaks its whole range outside the tunnel (see the
rem 2.0.0.0/7 notes in create_tun_dev.sh). Every destination must be the
rem network address of its own mask, like "route add 1.0.0.0 mask 255.0.0.0"
rem below - a /7 spelled as 1.0.0.0/254.0.0.0 describes 0.0.0.0/7, which
rem would swallow 0.0.0.0/8 as well. close_tun_dev_windows.bat has to delete
rem every block added here, with the same destination and mask.
call route add 1.0.0.0 mask 255.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 2.0.0.0 mask 254.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 4.0.0.0 mask 252.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 8.0.0.0 mask 248.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 16.0.0.0 mask 240.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 32.0.0.0 mask 224.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 64.0.0.0 mask 192.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route
call route add 128.0.0.0 mask 128.0.0.0 %tun_gw% metric 5
if errorlevel 1 set FAIL=route

if "%server_ip_v6%"=="" goto no_v6

call netsh interface ipv6 show addresses %tun_device% | findstr /C:" %tun_ip_sub_v6% " >nul 2>&1
if not errorlevel 1 (
    echo [create_tun_dev_windows] ipv6 address %tun_ip_sub_v6% already set on %tun_device%, skipped
    goto have_v6_addr
)
call netsh interface ipv6 add address %tun_device% %tun_ip_sub_v6%
if errorlevel 1 set FAIL=v6-address
:have_v6_addr

call netsh interface ipv6 set interface %tun_device% forwarding=enabled
if errorlevel 1 set FAIL=v6-forwarding

call netsh interface ipv6 show route | findstr /C:"::/1" >nul 2>&1
if not errorlevel 1 (
    echo [create_tun_dev_windows] ipv6 route ::/1 already set, skipped
    goto have_v6_route
)
call netsh interface ipv6 add route ::/1 %tun_device% metric=1
if errorlevel 1 set FAIL=v6-route
:have_v6_route

call netsh interface ipv6 add route 8000::/1 %tun_device% metric=1
if errorlevel 1 set FAIL=v6-route

:no_v6

rem Failing fast is not an option: the guards above run every command so the
rem single "failed near" line below reports the whole extent of the damage.
rem %FAIL% is expanded here, after every parenthesized block has closed, which
rem is the only place where that expansion is safe.
if defined FAIL (
    echo [create_tun_dev_windows] failed near: %FAIL% 1>&2
    exit /b 1
)
exit /b 0
