#!/bin/sh
tun_device=$1
tun_ip=$2
tun_gw=$3
local_gateway=$4
tun_ip_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# 退出码契约：调用方（fd/helper 路径下的 cmd/easyss/tun_helper_darwin.go，
# 以及无 helper 路径下的 client/tun/tun.go）仅在本脚本以 0 退出时才保留已
# 安装的 TUN 路由。所有不允许失败的命令都会调用 fail，把各自的步骤名记录到
# FAIL 中；脚本最后以显式 exit 结束。
#
# 本脚本刻意不使用 "set -e"。它会在睡眠/唤醒后被 helper 的 keep-alive 重新
# 执行，而一旦启用 "set -e"，第一条"已配置"的路由就会中止脚本，导致缺失的
# 路由无法被重新安装。退出码必须是脚本对自身运行过的每条命令给出的总体判定，
# 而不是恰好最后执行的那条命令的状态：路由是在设备地址之后安装的，因此一次被
# 拒绝的 ifconfig 或一次早期的路由添加失败，曾会被最后一条成功的路由添加掩盖
# ——正是 create_tun_dev_windows.bat 在 Windows 上引入 "exit /b" 契约之前
# 所报告的那种静默的半配置隧道。同样的契约也让 ensureTunRoutes 能区分成功的
# 重放与真正的失败，而不是每 10 秒记录一次警告并让 helper 退出。
set -u

FAIL=

# is_benign 用于判断一条失败命令的输出是否描述"状态已就位"的情况，
# 即重跑时合理出现的错误。macOS 的 "route add" 会拒绝重复添加路由
# （"File exists"），ifconfig 对已配置的地址也会报 "File exists"：
# keep-alive 会用上一次运行遗留的状态重新执行本脚本，因此这些错误
# 必须保持静默且视为成功。
is_benign() {
  case "$1" in
    *"File exists"* | *"already assigned"*) return 0 ;;
    *) return 1 ;;
  esac
}

# fail STEP COMMAND... 运行一条允许失败的命令，除非失败属于良性的
# "已配置"情况，否则把 STEP 记录到 FAIL 中。FAIL 与正在运行的命令共享
# 同一个 shell，因此记录发生在调用方的作用域内（无子 shell），并且只在
# 脚本末尾所有命令都执行完之后才展开。
fail() {
  step=$1
  shift

  if out="$("$@" 2>&1)"; then
    return 0
  fi

  if is_benign "$out"; then
    return 0
  fi

  echo "[create_tun_dev_darwin] $step ($*): $out" >&2
  FAIL="${FAIL:+$FAIL,}$step"
}

# 创建 tun 设备
fail ifconfig-ipv4 ifconfig "$tun_device" "$tun_ip" "$tun_gw" up
if [ -n "$server_ip_v6" ]; then  # 检查 server_ip_v6 是否非空
  # $tun_ip_v6 必须是裸地址：前缀长度由这里拼上，调用方（cmd/easyss 的
  # tun_helper_darwin.go 和 client/tun/tun.go）负责剥掉 TunIPV6Sub 自带的
  # 前缀。传入 "2001:db8::1/64" 会拼成 ".../64/64"，ifconfig 报 "bad value"。
  fail ifconfig-ipv6 ifconfig "$tun_device" inet6 "$tun_ip_v6"/64 up
fi

# 添加 IPv4 路由
fail route-1.0.0.0/8 route add -net 1.0.0.0/8 "$tun_gw"
fail route-2.0.0.0/7 route add -net 2.0.0.0/7 "$tun_gw"
fail route-4.0.0.0/6 route add -net 4.0.0.0/6 "$tun_gw"
fail route-8.0.0.0/5 route add -net 8.0.0.0/5 "$tun_gw"
fail route-16.0.0.0/4 route add -net 16.0.0.0/4 "$tun_gw"
fail route-32.0.0.0/3 route add -net 32.0.0.0/3 "$tun_gw"
fail route-64.0.0.0/2 route add -net 64.0.0.0/2 "$tun_gw"
fail route-128.0.0.0/1 route add -net 128.0.0.0/1 "$tun_gw"
fail route-198.18.0.0/15 route add -net 198.18.0.0/15 "$tun_gw"


if [ -n "$server_ip_v6" ]; then  # 检查 server_ip_v6 是否非空
  # 添加 IPv6 路由
  fail route-v6-default route add -inet6 -net ::/0 -gateway "$tun_gw_v6"
fi

if [ -n "$FAIL" ]; then
  echo "[create_tun_dev_darwin] failed near: $FAIL" >&2
  exit 1
fi
exit 0
