#!/bin/bash
tun_device=$1
tun_ip_sub=$2
tun_gw=$3
local_gateway=$4
tun_ip_sub_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# Exit code contract: the caller (cmd/easyss/tun_helper_linux.go, and
# client/tun/tun.go on the no-helper path) keeps the TUN routes installed only
# when this script exits 0. Every command that is not allowed to fail records
# its step name in FAIL below, and the script ends with an explicit exit.
#
# The failure steps are reported instead of swallowed because the script
# installs the address first and the routes after: a script that reports
# success after a rejected "ip route replace" leaves a half configured tunnel
# (traffic enters a device that reads nothing, or leaks outside the tunnel)
# while the tray claims system-wide traffic is on. The same contract is what
# create_tun_dev_windows.bat implements for cmd.exe, which propagates a
# missing "exit /b" as success.
#
# This script is re-run by the TUN helper keep-alive after sleep/wake and by
# every start, so re-applying already configured state must stay silent and
# successful: only the "already configured" errors of an idempotent command
# are tolerated (see run_idem / is_benign), a genuine rejection is not.
set -o pipefail

FAIL=

# is_benign reports whether the output of a failed command describes state
# that is already in place, i.e. an error a re-run legitimately produces.
# "File exists" is iproute2's "RTNETLINK answers: File exists" for an address
# or route that is already configured, which "ip addr replace" and "ip route
# replace" do not produce but a device that survived a crashed session can.
is_benign() {
  case "$1" in
    *"File exists"* | *"already assigned"*) return 0 ;;
    *) return 1 ;;
  esac
}

# run_idem STEP COMMAND... runs an idempotent ip command. A tolerated error
# stays silent (the keep-alive re-runs this script and must not report the
# same non-error every 10s); any other failure is echoed to stderr and
# recorded in FAIL, naming the step, so the caller learns the tunnel is only
# partly configured. FAIL belongs to the caller's shell: run_idem runs in it,
# not in a subshell, and the function deliberately does not declare it local.
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

run_idem addr ip addr replace "$tun_ip_sub" dev "$tun_device"  # add ipv4 addr to device
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  run_idem v6-addr ip -6 addr replace "$tun_ip_sub_v6" dev "$tun_device"  # add ipv6 addr to device
fi

run_idem link ip link set dev "$tun_device" up  # enable tun device

# Route everything except 0.0.0.0/8 through the TUN device, mirroring the
# darwin script. 0.0.0.1 (used to probe the physical default interface)
# must stay outside the TUN routes.
#
# The blocks below must form one contiguous ladder from 1.0.0.0 up to
# 255.255.255.255 (1.0.0.0/8 + 2.0.0.0/7 + 4.0.0.0/6 + ... + 128.0.0.0/1):
# skipping one leaks its whole range outside the tunnel. The missing
# 2.0.0.0/7 block sent every 2.x/3.x destination out of the physical NIC —
# the 3.x AWS addresses behind registry-1.docker.io included — so docker
# pulls became direct connections that the network resets instead of
# proxied ones. testCoveredAddrs and the coverage test in
# tun_helper_linux_test.go pin this down.
#
# Keep every prefix canonical (aligned with its own mask): 1.0.0.0/7
# normalizes to 0.0.0.0/7 and is rejected outright, which used to leave
# 1.0.0.0/8 leaking outside the tunnel.
run_idem route ip route replace 1.0.0.0/8 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 2.0.0.0/7 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 4.0.0.0/6 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 8.0.0.0/5 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 16.0.0.0/4 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 32.0.0.0/3 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 64.0.0.0/2 via "$tun_gw" dev "$tun_device"
run_idem route ip route replace 128.0.0.0/1 via "$tun_gw" dev "$tun_device"

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
  run_idem v6-route ip -6 route replace ::/1 via "$tun_gw_v6" dev "$tun_device"
  run_idem v6-route ip -6 route replace 8000::/1 via "$tun_gw_v6" dev "$tun_device"
fi

if [ -n "$FAIL" ]; then
  echo "[create_tun_dev] failed near: $FAIL" >&2
  exit 1
fi
exit 0
