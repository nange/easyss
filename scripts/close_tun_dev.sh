#!/bin/bash
# 关闭 TUN 会话：清空 TUN 设备上的路由，并在设备仍然存在时删掉它。
#
# 位置参数：1 设备名（其余位置参数由调用方按三平台统一的顺序传入，linux 路径不用）。
tun_device=$1

# 退出码契约：调用方（helper 退出前的清理，以及 client/tun 的关闭路径）依据本脚本
# 的退出码判断清理到底做成没有，并据此决定是否需要回滚。
set -u

if [ -z "$tun_device" ]; then
  echo "[close_tun_dev] missing tun device" >&2
  exit 1
fi

# 设备已经不存在时无需清理，也不是失败：非持久化 tun 设备随最后一个 fd 消失，
# 内核会同时删掉挂在它上面的路由（fd 路径的常态——主进程先停引擎关闭 fd，
# 提权 helper 随后才做清理）。这与"删除失败"必须区分开，否则每次正常关闭都会报错。
if ! ip link show "$tun_device" >/dev/null 2>&1; then
  exit 0
fi

FAIL=

# 先清路由再删设备：只要还有进程持有 TUN fd，`ip tuntap del` 就会以
# "device or resource busy" 失败，而这些分流路由会残留下来把流量黑洞掉。
if ! out="$(ip route flush dev "$tun_device" 2>&1)"; then
  echo "[close_tun_dev] flush ipv4 routes ($tun_device): $out" >&2
  FAIL="flush-ipv4"
fi

if ! out="$(ip -6 route flush dev "$tun_device" 2>&1)"; then
  echo "[close_tun_dev] flush ipv6 routes ($tun_device): $out" >&2
  FAIL="${FAIL:+$FAIL,}flush-ipv6"
fi

if ! out="$(ip tuntap del mode tun dev "$tun_device" 2>&1)"; then
  # 设备在两条命令之间消失属于良性竞态（并发关闭 fd 时必然出现）。
  case "$out" in
    *"Cannot find device"*) ;;
    *)
      echo "[close_tun_dev] delete tun device ($tun_device): $out" >&2
      FAIL="${FAIL:+$FAIL,}del-device"
      ;;
  esac
fi

if [ -n "$FAIL" ]; then
  echo "[close_tun_dev] failed near: $FAIL" >&2
  exit 1
fi
exit 0
