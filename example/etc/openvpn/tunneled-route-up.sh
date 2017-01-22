#! /bin/sh

# Which VPN connection to setup for
VPN="$(basename ${config} .conf)"

# Clear all routes on the vpn routing table
# (this is to make sure there isn't any crap left over from previous vpn connection)
ip route flush table "${VPN}"

# Add default gateway to vpn routing table
ip route add default via "${route_vpn_gateway}" dev "${dev}" table "${VPN}"

# Set the reverse path filter to "loose" for the tunnel interface
sysctl net.ipv4.conf."${dev}".rp_filter=2

