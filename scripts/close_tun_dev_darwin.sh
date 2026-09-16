#!/bin/sh
tun_device=$1
tun_gw=$2
local_gateway=$3
tun_gw_v6=$4
server_ip_v6=$5
local_gateway_v6=$6

route delete -net 1.0.0.0/8 "$tun_gw"
route delete -net 2.0.0.0/7 "$tun_gw"
route delete -net 4.0.0.0/6 "$tun_gw"
route delete -net 8.0.0.0/5 "$tun_gw"
route delete -net 16.0.0.0/4 "$tun_gw"
route delete -net 32.0.0.0/3 "$tun_gw"
route delete -net 64.0.0.0/2 "$tun_gw"
route delete -net 128.0.0.0/1 "$tun_gw"
route delete -net 198.18.0.0/15 "$tun_gw"

# 创建脚本不再把本地网关路由进 TUN 设备：指向它的主机路由会吞掉内核发往
# 网关自身存活探测的 ICMP 回复（参见 scripts/create_tun_dev.sh）。这条删除
# 命令仍然保留，因为 darwin 在重启后仍会保留路由表，所以它负责清理
# 旧版本安装的路由。
route delete -net "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then
  route delete -inet6 -net ::/0 -gateway "$tun_gw_v6"

  # 与上面的 IPv4 网关路由同理：仅清理残留的旧路由。
  route delete -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi
