#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
local_gateway=$4
tun_ip_sub_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# run_idem runs an idempotent ip command, tolerating the errors that
# re-applying an already configured address produces (this script is re-run by
# the TUN helper keep-alive after sleep/wake; replace/route replace are
# no-ops that exit 0). Any other failure is echoed to stderr instead of being
# swallowed silently: a rejected route (e.g. a non-canonical prefix) used to
# leave the tunnel half configured with no trace at all.
run_idem() {
  local out
  out="$("$@" 2>&1)" || case "$out" in
    *"File exists"* | *"already assigned"*) ;;
    *) echo "[create_tun_dev] $*: $out" >&2 ;;
  esac
}

run_idem ip addr replace "$tun_ip_sub" dev "$tun_device"  # add ipv4 addr to device
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  run_idem ip -6 addr replace "$tun_ip_sub_v6" dev "$tun_device"  # add ipv6 addr to device
fi

run_idem ip link set dev "$tun_device" up  # enable tun device

# Route everything except 0.0.0.0/8 through the TUN device, mirroring the
# darwin script. 0.0.0.1 (used to probe the physical default interface)
# must stay outside the TUN routes. Keep every prefix canonical (aligned with
# its own mask): 1.0.0.0/7 normalizes to 0.0.0.0/7 and is rejected outright,
# which used to leave 1.0.0.0/8 leaking outside the tunnel.
run_idem ip route replace 1.0.0.0/8 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 4.0.0.0/6 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 8.0.0.0/5 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 16.0.0.0/4 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 32.0.0.0/3 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 64.0.0.0/2 via "$tun_gw" dev "$tun_device"
run_idem ip route replace 128.0.0.0/1 via "$tun_gw" dev "$tun_device"

# The local gateway ($local_gateway and $local_gateway_v6) is deliberately NOT
# routed into the TUN device. A bare address is installed as a /32 host route,
# so it would beat the physical interface's on-link connected route (e.g.
# 192.168.3.0/24) and pull every packet addressed to the gateway into the
# tunnel — including the kernel's ICMP echo replies to the gateway's own
# liveness probes. tun2socks' default ICMP forwarder only answers echo
# requests (type 8) and drops every other type, so those replies never reach
# the gateway: it keeps probing forever (observed as several [ICMP_DIRECT]
# log lines per second) and `ping <gateway>` only ever reports a synthetic
# sub-millisecond reply. The gateway must therefore stay on the physical
# interface, exactly like the darwin script, which dropped the same route in
# 91bb4c6 ("fix: ip route on darwin when enable tun2socks").

# add ipv6 ip route
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  run_idem ip -6 route replace ::/1 via "$tun_gw_v6" dev "$tun_device"
  run_idem ip -6 route replace 8000::/1 via "$tun_gw_v6" dev "$tun_device"
fi
