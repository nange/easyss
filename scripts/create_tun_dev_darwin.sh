#!/bin/sh
tun_device=$1
tun_ip=$2
tun_gw=$3
local_gateway=$4
tun_ip_v6=$5
tun_gw_v6=$6
server_ip_v6=$7
local_gateway_v6=$8

# Exit code contract: the caller (cmd/easyss/tun_helper_darwin.go on the
# fd/helper path, client/tun/tun.go on the no-helper path) keeps the TUN
# routes installed only when this script exits 0. Every command that is not
# allowed to fail calls fail, which records its step name in FAIL; the script
# ends with an explicit exit.
#
# This script has no "set -e" on purpose. It is re-run by the helper keep-alive
# after sleep/wake, and with "set -e" the first already configured route would
# abort it before the missing ones were re-installed. The exit code has to be
# the script's own verdict over every command it ran, not the status of
# whichever command happened to come last: the routes are installed after the
# device address, so a rejected ifconfig or an early rejected route add used to
# be masked by the success of the last route add — the same silently half
# configured tunnel create_tun_dev_windows.bat reported on Windows before its
# "exit /b" contract. The same contract also lets ensureTunRoutes tell a
# successful re-apply from a genuine failure instead of logging a warning every
# 10s and making the helper exit.
set -u

FAIL=

# is_benign reports whether the output of a failed command describes state that
# is already in place, i.e. an error a re-run legitimately produces. macOS
# "route add" refuses to duplicate a route ("File exists"), and ifconfig
# reports "File exists" for an address that is already configured: the keep
# alive re-runs this script against the state the previous run left behind, so
# those have to stay silent and successful.
is_benign() {
  case "$1" in
    *"File exists"* | *"already assigned"*) return 0 ;;
    *) return 1 ;;
  esac
}

# fail STEP COMMAND... runs a command that is allowed to fail and records STEP
# in FAIL unless the failure is the benign "already configured" case. FAIL and
# the running command share this shell, so the recording happens in the
# caller's scope (no subshell) and is expanded only at the end of the script,
# where every command has run.
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

# create tun device
fail ifconfig-ipv4 ifconfig "$tun_device" "$tun_ip" "$tun_gw" up
if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  fail ifconfig-ipv6 ifconfig "$tun_device" inet6 "$tun_ip_v6"/64 up
fi

# add ipv4 ip route
fail route-1.0.0.0/8 route add -net 1.0.0.0/8 "$tun_gw"
fail route-2.0.0.0/7 route add -net 2.0.0.0/7 "$tun_gw"
fail route-4.0.0.0/6 route add -net 4.0.0.0/6 "$tun_gw"
fail route-8.0.0.0/5 route add -net 8.0.0.0/5 "$tun_gw"
fail route-16.0.0.0/4 route add -net 16.0.0.0/4 "$tun_gw"
fail route-32.0.0.0/3 route add -net 32.0.0.0/3 "$tun_gw"
fail route-64.0.0.0/2 route add -net 64.0.0.0/2 "$tun_gw"
fail route-128.0.0.0/1 route add -net 128.0.0.0/1 "$tun_gw"
fail route-198.18.0.0/15 route add -net 198.18.0.0/15 "$tun_gw"


if [ -n "$server_ip_v6" ]; then  # check if server_ip_v6 is not empty
  # add ipv6 ip route
  fail route-v6-default route add -inet6 -net ::/0 -gateway "$tun_gw_v6"
fi

if [ -n "$FAIL" ]; then
  echo "[create_tun_dev_darwin] failed near: $FAIL" >&2
  exit 1
fi
exit 0
