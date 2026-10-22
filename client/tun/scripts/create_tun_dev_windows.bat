echo "Please wait a moment... This window will be closed after the operation completed"
@echo off

rem 本文件必须保持 CRLF 行尾与 UTF-8（无 BOM）编码：cmd.exe 按 OEM 代码页逐行读取
rem 批处理文件，在中文 Windows（OEM 代码页 936）上，LF 行尾会让多字节注释的字节与换行
rem 错位，注释文字被当成命令执行（已实测）。这里曾经要求"注释保持 ASCII"，针对的是同一个
rem 担心，但中文注释本身是安全的：UTF-8 的每个字节都 ≥ 0x80，不带 cmd 的特殊字符。
rem .gitattributes 的 "*.bat text eol=crlf" 保证检出即 CRLF，scripts_test.go 另有断言兜底。

set tun_device=%1
set tun_ip=%2
set tun_gw=%3
set tun_mask=%4
set tun_ip_sub_v6=%5
set tun_gw_v6=%6
rem 下面两个可选参数会去掉实参两端的引号。这点很关键：Go 把空参数编码成字面量 ""，
rem cmd 会把这组引号保留在批处理参数里，于是普通的 "%server_ip_v6%" 看起来非空，脚本
rem 就会在服务端没有 ipv6 可承载时错误地装上 ipv6 路由（地址、::/1 与 8000::/1）。
rem 本文件里绝不能写出参数路径修饰符的完整形式（百分号、波浪号加一个非数字），哪怕是在
rem 注释里：cmd 会以 "usage of the path operator in batch-parameter substitution is
rem invalid" 拒绝整个脚本，下面一行都不会执行。
set server_ip_v6=%~7
set tun_dns=%~8
set tun_mtu=%~9

rem 退出码契约：只有本脚本以 0 退出，调用方（client/tun/tun.go）才会保留已安装的 TUN
rem 路由。cmd.exe 传播的是最后一条被执行的命令的退出码，因此没有显式 "exit /b" 的批处理
rem 文件即使中间有 netsh/route 命令被拒绝也会报告成功：下面每条命令都把自己的失败记进
rem FAIL，脚本最后用显式的 "exit /b" 收尾。
rem
rem 每个守卫都写成 "call X || set FAIL=<步骤>"："call" 让脚本在 X 是 PATH 上的 .bat/.cmd
rem 工具时继续跑下去（没有它，cmd.exe 会在那里以 X 的退出码结束整个脚本），而 "|| set"
rem 响应的是 X 运行时的退出码——写在 X 那一行里的 "%ERRORLEVEL%" 会在 X 运行之前就展开。
rem
rem "set address" 与 "set dns" 是幂等的重复应用。add 类命令可能与没有干净关闭的上一个
rem 会话留下的东西（路由、v6 地址）冲突；创建失败的回滚与关闭脚本会清掉这些残留，重试
rem 即可成功，所以这里不需要只读的"已经配置过"预检。
set FAIL=

call netsh interface ipv4 set address %tun_device% static address=%tun_ip% mask=%tun_mask% gateway=%tun_gw% || set FAIL=address

rem DNS 服务器由调用方（cmd/easyss 的 tunDNS）计算并作为第 8 个参数传入，使 Windows 与
rem darwin/linux 用同一个值：本次会话实测能应答的那个解析器（内置直连 DNS，退化时回落到
rem 系统解析器）。它与 enable_forward_dns 无关，后者只服务 0.0.0.0:53 上的局域网客户端。
rem 参数为空时适配器保持默认配置，这不是失败。
rem 本块的编码与行尾要求见文件头（这里是过去那条"保持 ASCII"约定的位置）。
if not "%tun_dns%"=="" call netsh interface ipv4 set dns name=%tun_device% static %tun_dns% || set FAIL=dns

rem MTU 由调用方（client/tun/tun.go，来自唯一的 tun_mtu 旋钮）计算并作为第 9 个参数传入，
rem 必须在这里应用：tun2socks 设不了 wintun 适配器的 MTU——wireguard-go 只把它记在内存里，
rem 并从 MTU() 报回来（见 tun_windows.go 的 forcedMTU）——而它的 netstack 按同一个值运行，
rem 会静默丢弃从设备读到的、超过自身 MTU 的包（UDP、ICMP 与 IP 分片）。netsh 是唯一能改
rem 这个适配器的途径，store=active 让这次改动只作用于本会话，而不是写进注册表。
rem 参数为空表示调用方没有传 MTU（更早的布局）：适配器保持默认配置，这不是失败。
if "%tun_mtu%"=="" goto no_mtu
call netsh interface ipv4 set subinterface "%tun_device%" mtu=%tun_mtu% store=active || set FAIL=mtu
:no_mtu

rem 除 0.0.0.0/8 之外的流量都走 TUN 设备，与 darwin 脚本一致。0.0.0.1（用来探测物理默认
rem 接口）必须留在 TUN 路由之外。
rem
rem 下面这些块必须从 1.0.0.0 一路连续排到 255.255.255.255（1.0.0.0/8 + 2.0.0.0/7 +
rem 4.0.0.0/6 + ... + 128.0.0.0/1）：漏掉一个块就会让整段范围绕开隧道（见
rem create_tun_dev.sh 里关于 2.0.0.0/7 的说明）。每个目的地址都必须是它自己掩码的网络
rem 地址，就像下面的 "route add 1.0.0.0 mask 255.0.0.0"——把 /7 写成
rem 1.0.0.0/254.0.0.0 描述的是 0.0.0.0/7，那会把 0.0.0.0/8 一起吞掉。
rem close_tun_dev_windows.bat 必须用相同的目的地址与掩码删掉这里添加的每一个块。
call route add 1.0.0.0 mask 255.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 2.0.0.0 mask 254.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 4.0.0.0 mask 252.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 8.0.0.0 mask 248.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 16.0.0.0 mask 240.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 32.0.0.0 mask 224.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 64.0.0.0 mask 192.0.0.0 %tun_gw% metric 5 || set FAIL=route
call route add 128.0.0.0 mask 128.0.0.0 %tun_gw% metric 5 || set FAIL=route

if "%server_ip_v6%"=="" goto no_v6

rem 那个持久化的 v6 地址还在适配器上时，"add address" 会拒绝重复添加；关闭脚本会删掉它，
rem 所以这里保持无条件 add。
call netsh interface ipv6 add address %tun_device% %tun_ip_sub_v6% || set FAIL=v6-address
call netsh interface ipv6 set interface %tun_device% forwarding=enabled || set FAIL=v6-forwarding
rem ipv6 的 MTU 只在隧道真的承载 ipv6 时才有意义，所以放在这个分支里应用。1280 的下限由
rem 调用方（config.NormalizeTunMTU）保证，它同时也是 ipv6 的最小链路 MTU。
rem goto 让 "|| set FAIL" 留在任何 if 体之外，与文件里其他命令保持一致。
if "%tun_mtu%"=="" goto no_v6_mtu
call netsh interface ipv6 set subinterface "%tun_device%" mtu=%tun_mtu% store=active || set FAIL=v6-mtu
:no_v6_mtu
call netsh interface ipv6 add route ::/1 %tun_device% metric=1 || set FAIL=v6-route
call netsh interface ipv6 add route 8000::/1 %tun_device% metric=1 || set FAIL=v6-route

:no_v6

rem %FAIL% 记录最后一个失败的步骤；在所有命令都跑完之后再展开它是安全的——放进更早的
rem 括号块里会过早展开。
if defined FAIL (
    echo [create_tun_dev_windows] failed near: %FAIL% 1>&2
    exit /b 1
)
exit /b 0
