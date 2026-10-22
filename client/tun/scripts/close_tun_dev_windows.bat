@echo off

rem 本文件必须保持 CRLF 行尾与 UTF-8（无 BOM）编码：cmd.exe 按 OEM 代码页逐行读取
rem 批处理文件，在中文 Windows（OEM 代码页 936）上，LF 行尾会让多字节注释的字节与
rem 换行错位，注释文字被当成命令执行（已实测）。.gitattributes 的
rem "*.bat text eol=crlf" 保证检出即 CRLF，scripts_test.go 另有断言兜底。

set tun_device=%1
set tun_gw=%2
set tun_ip_v6=%3

rem TUN 网关既是下面每条删除的目标，也是文件末尾残留探测的匹配依据。空网关不是良性
rem 状态："route delete ... 空网关" 会丢掉网关参数，从而可能删掉物理链路上的同名路由。
rem linux/darwin 的关闭脚本同样拒绝这种输入。
if "%tun_gw%"=="" (
    echo [close_tun_dev_windows] missing tun gateway 1>&2
    exit /b 1
)

rem 设备已经不存在时无需清理，也不是失败：停止 tun2socks 会关闭 wintun 适配器
rem （NativeTun.Close 到 WintunCloseAdapter），适配器随即从系统注销，Windows 连同该
rem 接口上的路由与 ipv6 地址一起收走。这是三个平台共同的顺序——引擎先停、关闭脚本后跑
rem （见 client/tun/tun.go 的 Manager.Stop）——所以 linux 与 darwin 也有同样的守卫
rem （close_tun_dev.sh 问 "ip link show"，close_tun_dev_darwin.sh 把"路由不在表里"当
rem 良性）。少了它，每次正常关闭都会把十一条"对象已不存在"的删除报成一次清理失败。
rem
rem 判据是 netsh 的退出码而不是它的输出：接口未注册时 netsh 打印的是
rem "The filename, directory name, or volume label syntax is incorrect."，它与真正的
rem 失败无法从文本上区分，而且随系统语言变化。退出码必须恰好为 1（那才是 netsh 对未注册
rem 接口的回答）：netsh 自己跑不起来（9009）时必须落到下面的删除与残留探测，而不是冒充
rem "设备已消失"，否则真正残留下来的路由会被掩盖掉。
call netsh interface show interface name="%tun_device%" >nul 2>&1
if errorlevel 1 if not errorlevel 2 exit /b 0

rem 尽力而为的清理：删除仍可能良性失败（对象本来就不存在——创建脚本只在服务端有 ipv6
rem 时才安装 v6 地址与路由）。"call" 让脚本在 PATH 上的某个工具是失败退出的 .bat/.cmd
rem 时继续跑下去，一条删除失败不会跳过其余的。
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

rem netsh add address 是持久化的，而创建脚本的 "add address" 拒绝重复添加，所以 v6 地址
rem 必须在这里删掉，下一次启动（以及创建失败后的回滚）才能成功。
rem 第三个参数是不带 /prefix 的裸地址，"netsh delete address" 要的正是这种形式。
if not "%tun_ip_v6%"=="" call netsh interface ipv6 delete address %tun_device% %tun_ip_v6%

rem 退出码契约：只有本脚本以 0 退出，调用方（client/tun/tun.go 的 Stop() 与各条回滚路径）
rem 才会认为路由已经清干净——残留的分流默认路由会把全机 IPv4 流量送进一个没人读的设备。
rem 单条 netsh 命令的退出码回答不了这个问题：对象本来就不存在时它是 1，删除真被拒绝时它
rem 也是 1；而没有显式 "exit /b" 时，cmd.exe 会把最后一条命令的退出码当成脚本的。
rem 所以这里直接问路由表。
rem
rem 残留只认本脚本删过的那 8 条分流默认路由（目的地址在这 8 个里、网关是 TUN 网关）。
rem 不能只看"网关等于 TUN 网关"：创建脚本的 "set address ... gateway" 会给适配器自己配
rem 一条默认路由，Windows 把它作为持久路由留在表里（实测），别的 VPN 客户端也可能装上
rem 0/1、128/1 这类大段路由——它们都不归本脚本删，算成残留只会让调用方每次关闭都告警。
rem
rem "route print -4" 的第 1、3 列是目的地址与网关，因此这与本地化的表头无关；列数不足
rem 三列的行（接口列表）匹配不上网关。
set RESIDUE=
for /f "tokens=1,2,3" %%a in ('route print -4') do (
    if "%%c"=="%tun_gw%" for %%p in (1.0.0.0 2.0.0.0 4.0.0.0 8.0.0.0 16.0.0.0 32.0.0.0 64.0.0.0 128.0.0.0) do (
        if "%%a"=="%%p" set RESIDUE=1
    )
)
if defined RESIDUE (
    echo [close_tun_dev_windows] residual split routes via %tun_gw% 1>&2
    exit /b 1
)
exit /b 0
