#!/bin/sh
# 关闭 TUN 会话：删除创建脚本安装的分流默认路由。
#
# 位置参数（顺序是调用方与脚本之间的契约，见 client/tun/tun.go 的
# closeTunDevAndDelIPRoute 与 cmd/easyss/tun_helper_darwin.go 的 runCloseScript）：
#   1 设备名 2 tun gw 3 本地网关 4 tun gw ipv6 5 服务端 ipv6 6 本地网关 ipv6
#
# 第 1 个参数（设备名）不参与删除：这些路由是按网关安装的，而且 fd 路径下调用方
# 只知道请求的设备名，不知道内核实际分配的 utunN。按网关删除还有个好处：设备已经
# 随最后一个 fd 消失时，残留的路由仍然能被清掉——那正是"停止 TUN 后断网"的成因。
tun_device=$1
tun_gw=$2
local_gateway=$3
tun_gw_v6=$4
server_ip_v6=$5
local_gateway_v6=$6

# 退出码契约：调用方（helper 退出前的清理，以及 client/tun 的关闭路径）依据本脚本
# 的退出码判断路由到底删掉没有，并据此决定是否需要回滚。过去每条 route delete 的
# 失败都被静默忽略，于是残留的分流默认路由把全机 IPv4 流量送进一个没人读的设备，
# 用户看到的就是"停止 TUN 后网络已断开"。
#
# 变量未设置必须报错而不是当空串用：`route delete -net 1.0.0.0/8 ""` 可能被解释成
# "不指定网关地删除该前缀"，从而删掉物理网卡上的同名路由。
set -u

if [ -z "$tun_gw" ]; then
  echo "[close_tun_dev_darwin] missing tun gateway" >&2
  exit 1
fi

FAIL=

# is_benign 判断失败输出是否只是"状态已经就位"：路由本来就不存在（重复关闭、
# keep-alive 重放、从未安装过 v6 路由的会话）不是失败。
is_benign() {
  case "$1" in
    *"not in table"* | *"bad value"* | *"No such process"* | *"not found"*) return 0 ;;
    *) return 1 ;;
  esac
}

# del STEP COMMAND... 运行一条允许失败的删除命令；只有真正的失败会记入 FAIL，
# 并在脚本末尾统一上报。与创建脚本的 fail 保持同一种写法。
del() {
  step=$1
  shift

  if out="$("$@" 2>&1)"; then
    return 0
  fi

  if is_benign "$out"; then
    return 0
  fi

  echo "[close_tun_dev_darwin] $step ($*): $out" >&2
  FAIL="${FAIL:+$FAIL,}$step"
}

del route-1.0.0.0/8 route delete -net 1.0.0.0/8 "$tun_gw"
del route-2.0.0.0/7 route delete -net 2.0.0.0/7 "$tun_gw"
del route-4.0.0.0/6 route delete -net 4.0.0.0/6 "$tun_gw"
del route-8.0.0.0/5 route delete -net 8.0.0.0/5 "$tun_gw"
del route-16.0.0.0/4 route delete -net 16.0.0.0/4 "$tun_gw"
del route-32.0.0.0/3 route delete -net 32.0.0.0/3 "$tun_gw"
del route-64.0.0.0/2 route delete -net 64.0.0.0/2 "$tun_gw"
del route-128.0.0.0/1 route delete -net 128.0.0.0/1 "$tun_gw"
del route-198.18.0.0/15 route delete -net 198.18.0.0/15 "$tun_gw"

# 创建脚本不再把本地网关路由进 TUN 设备：指向它的主机路由会吞掉内核发往
# 网关自身存活探测的 ICMP 回复（参见 scripts/create_tun_dev.sh）。这条删除
# 命令仍然保留，因为 darwin 在重启后仍会保留路由表，所以它负责清理
# 旧版本安装的路由；路由不存在时属于良性情况。
del route-local-gateway route delete -net "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then
  del route-v6-default route delete -inet6 -net ::/0 -gateway "$tun_gw_v6"

  # 与上面的 IPv4 网关路由同理：仅清理残留的旧路由。
  del route-v6-local-gateway route delete -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi

if [ -n "$FAIL" ]; then
  echo "[close_tun_dev_darwin] failed near: $FAIL" >&2
  exit 1
fi
exit 0
