#!/bin/bash
tun_device=$1

# 在删除接口之前先清空 TUN 路由。删除接口本身也会清掉这些路由，但只要有
# 进程仍持有 TUN 文件描述符，删除就会以 "device or resource busy" 失败
# （iproute2 通过 TUNSETIFF 附着，而客户端会与执行本脚本并发关闭其 fd），
# 拆分后的路由便会残留下来：所有发往这些路由的连接都会进入一个无人读取的
# 接口，停止 TUN 后便表现为"网络已断开"。当接口已不存在时，尽力而为且保持静默。
ip route flush dev "$tun_device" >/dev/null 2>&1
ip -6 route flush dev "$tun_device" >/dev/null 2>&1

ip tuntap del mode tun dev "$tun_device"
