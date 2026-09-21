echo "Please wait a moment... This window will be closed after the operation completed"
@echo off

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set tun_ip_sub_v6=%5
set tun_gw_v6=%6
rem "%~N" strips the surrounding quotes. It matters for the optional arguments:
rem Go encodes an empty argument as a literal "" and cmd keeps those quotes in a
rem batch parameter, so a plain "%server_ip_v6%" would look non-empty and the
rem script would wrongly install the ipv6 routes (address, ::/1 and 8000::/1)
rem on a tunnel whose server has no ipv6 to carry them.
set server_ip_v6=%~7
set tun_dns=%~8

rem Exit code contract: the caller (client/tun/tun.go) keeps the TUN routes
rem installed only when this script exits 0. cmd.exe propagates the exit
rem code of the LAST executed command, so a batch file without an explicit
rem "exit /b" reports success even when an earlier netsh/route command was
rem rejected: every command below records its failure into FAIL, and the
rem script ends with an explicit "exit /b".
rem
rem Every guard is "call X || set FAIL=<step>": "call" keeps the script
rem running when X is a .bat/.cmd tool on PATH (without it cmd.exe ends the
rem whole script there with X's exit code), and "|| set" reacts to X's exit
rem code at runtime - "%ERRORLEVEL%" on X's own line would expand before X
rem runs.
rem
rem "set address" and "set dns" are idempotent re-applies. The add commands
rem can collide with what a session that was not closed cleanly left behind
rem (routes, v6 address); the rollback of a failed create and the close
rem script remove those leftovers and a retry succeeds, so no command needs
rem a read-only "already configured" pre-check here.
set FAIL=

call netsh interface ipv4 set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw% || set FAIL=address

rem The DNS server is computed by the caller (cmd/easyss tunDNS) and passed as
rem the 8th argument, so Windows uses the same value as darwin/linux: 127.0.0.1
rem (the local forward DNS server) when enable_forward_dns is set, otherwise the
rem builtin direct DNS that answered during this session. When the argument is
rem empty the adapter keeps its default configuration, which is not a failure.
rem Keep this block ASCII-only: cmd.exe reads the file in the OEM code page.
if not "%tun_dns%"=="" call netsh interface ipv4 set dns name=%tun_device% static %tun_dns% || set FAIL=dns

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
call route add 1.0.0.0 mask 255.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 2.0.0.0 mask 254.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 4.0.0.0 mask 252.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 8.0.0.0 mask 248.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 16.0.0.0 mask 240.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 32.0.0.0 mask 224.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 64.0.0.0 mask 192.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 128.0.0.0 mask 128.0.0.0 %tun_gw% metric 5 || set FAIL=route

if "%server_ip_v6%"=="" goto no_v6

rem "add address" refuses to duplicate the persistent v6 address while it is
rem still on the adapter; close_tun_dev_windows.bat deletes it, so this
rem stays an unconditional add.
call netsh interface ipv6 add address %tun_device% %tun_ip_sub_v6% || set FAIL=v6-address
call netsh interface ipv6 set interface %tun_device% forwarding=enabled || set FAIL=v6-forwarding
call netsh interface ipv6 add route ::/1 %tun_device% metric=1 || set FAIL=v6-route
call netsh interface ipv6 add route 8000::/1 %tun_device% metric=1 || set FAIL=v6-route

:no_v6

rem %FAIL% names the last step that failed; expanding it here, after every
rem command has run, is safe - inside an earlier parenthesized block it
rem would expand too early.
if defined FAIL (
    echo [create_tun_dev_windows] failed near: %FAIL% 1>&2
    exit /b 1
)
exit /b 0
