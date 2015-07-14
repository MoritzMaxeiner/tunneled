#!/bin/sh

# Which VPN connection to setup for
VPN="$(basename ${config} .conf)"

# Clear all routes on the vpn routing table
# (this is to make sure there isn't any crap left over from previous vpn connection)
/sbin/ip route flush table openvpn."${VPN}"

# Copy main routing table into vpn routing table
/sbin/ip route show table main | grep -Ev ^default | while read ROUTE ; do /sbin/ip route add table openvpn."${VPN}" "${ROUTE}"; done

# Add default gateway to vpn routing table
/sbin/ip route add default via "${route_vpn_gateway}" dev "${dev}" table openvpn."${VPN}"

# Set the reverse path filter to "loose" for the tunnel interface
/sbin/sysctl net.ipv4.conf."${dev}".rp_filter=2

