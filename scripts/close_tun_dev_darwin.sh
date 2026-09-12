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

# The create script no longer routes the local gateway into the TUN device: a
# host route to it swallowed the kernel's ICMP replies to the gateway's own
# liveness probes (see scripts/create_tun_dev.sh). The delete stays because
# darwin keeps routes in the table across restarts, so it cleans up the route
# older versions installed.
route delete -net "$local_gateway" "$tun_gw"

if [ -n "$server_ip_v6" ]; then
  route delete -inet6 -net ::/0 -gateway "$tun_gw_v6"

  # Same as the IPv4 gateway route above: stale routes only.
  route delete -inet6 -net "$local_gateway_v6" -gateway "$tun_gw_v6"
fi
