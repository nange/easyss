#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
local_gateway=$4
tun_ip_sub_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# 退出码契约：调用方（cmd/easyss/tun_helper_linux.go，以及无 helper 路径下的
# client/tun/tun.go）仅在本脚本以 0 退出时才保留已安装的 TUN 路由。所有不允许
# 失败的命令都会把各自的步骤名记录到 FAIL 中，脚本最后以显式 exit 结束。
#
# 失败步骤会被上报而不是吞掉，因为本脚本先安装地址、后安装路由：如果一条被
# 拒绝的 "ip route replace" 之后脚本仍报告成功，就会留下一个半配置的隧道
# （流量进入一个无人读取的设备，或泄漏到隧道之外），而托盘却声称全局流量
# 已开启。同样的契约也是 create_tun_dev_windows.bat 为 cmd.exe 实现的，
# 缺少 "exit /b" 会被它当作成功传播。
#
# 本脚本会在睡眠/唤醒后被 TUN helper 的 keep-alive 重新执行，每次启动也会
# 执行，因此重复应用已配置的状态必须保持静默且成功：只有幂等命令报出的
# "已配置"类错误才被容忍（参见 run_idem / is_benign），真正的拒绝则不会被容忍。
set -o pipefail

FAIL=

# is_benign 用于判断一条失败命令的输出是否描述"状态已就位"的情况，
# 即重跑时合理出现的错误。"File exists" 对应 iproute2 对已配置的地址
# 或路由报出的 "RTNETLINK answers: File exists"，"ip addr replace" 和
# "ip route replace" 不会产生该错误，但崩溃会话后幸存的设备可以。
is_benign() {
  case "$1" in
    *"File exists"* | *"already assigned"*) return 0 ;;
    *) return 1 ;;
  esac
}

# run_idem STEP COMMAND... 运行一条幂等的 ip 命令。可容忍的错误保持静默
# （keep-alive 会重新执行本脚本，不能在每 10 秒里反复报告同一个非错误）；
# 任何其他失败都会回显到 stderr 并记录到 FAIL 中，并注明步骤名，以便调用方
# 得知隧道只配置了一部分。FAIL 属于调用方的 shell：run_idem 在其中运行，
# 而不是在子 shell 中，且该函数刻意不将其声明为 local。
run_idem() {
  local step=$1 out
  shift

  if out="$("$@" 2>&1)"; then
    return 0
  fi

  if is_benign "$out"; then
    return 0
  fi

  echo "[create_tun_dev] $step ($*): $out" >&2
  FAIL="${FAIL:+$FAIL,}$step"
}

run_idem addr ip addr replace "$tun_ip_sub" dev "$tun_device"  # 为设备添加 IPv4 地址
if [ -n "$server_ip_v6" ]; then  # 检查 server_ip_v6 是否非空
  run_idem v6-addr ip -6 addr replace "$tun_ip_sub_v6" dev "$tun_device"  # 为设备添加 IPv6 地址
fi

run_idem link ip link set dev "$tun_device" up  # 启用 tun 设备

# 除 0.0.0.0/8 外的所有流量都路由进 TUN 设备，与 darwin 脚本保持一致。
# 0.0.0.1（用于探测物理默认接口）必须留在 TUN 路由之外。
#
# 下面的路由块必须构成从 1.0.0.0 到 255.255.255.255 的一段连续阶梯
# （1.0.0.0/8 + 2.0.0.0/7 + 4.0.0.0/6 + ... + 128.0.0.0/1）：
# 跳过任何一块都会让它的整个网段泄漏到隧道之外。缺失的 2.0.0.0/7 块
# 曾把所有 2.x/3.x 目标都送出物理网卡——包括 registry-1.docker.io 背后的
# 3.x AWS 地址——导致 docker 拉取变成直连而被网络重置，而不是走代理。
# testCoveredAddrs 和 tun_helper_linux_test.go 中的覆盖测试锁定了这一点。
#
# 每个前缀都必须保持规范形式（与其掩码对齐）：1.0.0.0/7 会被规范化为
# 0.0.0.0/7 并被直接拒绝，过去这曾导致 1.0.0.0/8 泄漏到隧道之外。
run_idem route ip route replace 1.0.0.0/8 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 2.0.0.0/7 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 4.0.0.0/6 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 8.0.0.0/5 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 16.0.0.0/4 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 32.0.0.0/3 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 64.0.0.0/2 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 128.0.0.0/1 via "$tun_gw" dev "$tun_device"

# 本地网关（$local_gateway 和 $local_gateway_v6）刻意不路由进 TUN 设备。
# 裸地址会被安装为 /32 主机路由，因此它会压过物理接口的 on-link 直连路由
# （例如 192.168.3.0/24），把所有发往网关的包都拉进隧道——包括内核针对
# 网关自身存活探测发出的 ICMP 回显回复。tun2socks 默认的 ICMP 转发器只应答
# 回显请求（type 8）并丢弃其他所有类型，所以这些回复永远到不了网关：
# 网关会一直探测下去（表现为每秒数条 [ICMP_DIRECT] 日志），而
# `ping <gateway>` 只会报告一条合成的亚毫秒级回复。因此网关必须留在物理
# 接口上，与 darwin 脚本完全一致——后者在 91bb4c6（"fix: ip route on darwin
# when enable tun2socks"）中删掉了同一条路由。

# 添加 IPv6 路由
if [ -n "$server_ip_v6" ]; then  # 检查 server_ip_v6 是否非空
  run_idem v6-route ip -6 route replace ::/1 via "$tun_gw_v6" dev "$tun_device"
  run_idem v6-route ip -6 route replace 8000::/1 via "$tun_gw_v6" dev "$tun_device"
fi

if [ -n "$FAIL" ]; then
  echo "[create_tun_dev] failed near: $FAIL" >&2
  exit 1
fi
exit 0
