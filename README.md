## Capabilities

In order to run as a normal user tunneled requires two `capabilities(7)` in its permitted set:
- `CAP_NET_ADMIN`: Changing network settings (addresses, routes, devices, etc)
- `CAP_DAC_OVERRIDE`: Manage the `cgroups(7)` used to select which program(s) are affected

### Programs

The following programs are called by tunneled to make changes to the system, but they themselves are not aware of capabilities, but instead expect to be called as a privileged user. That means in order for them to work properly, they need to have the relevent `capabilities(7)` set in their inherited set (so they are allowed to inherit them) *and* have the effective flag set (so they the capabilities become effective at call time).

- `sysctl`: `CAP_NET_ADMIN`
- `ip`: `CAP_NET_ADMIN`
- `nft`: `CAP_NET_ADMIN`
- `cgcreate`: `CAP_DAC_OVERRIDE`
- `cgdelete`: `CAP_DAC_OVERRIDE`

__Used for openvpn__:
- `openvpn`: `CAP_NET_ADMIN`
- `ifconfig`: `CAP_NET_ADMIN`

__Used for openconnect__:
- `openconnect`: `CAP_NET_ADMIN`

Since it is likely your Linux distribution does not do the above by default, you'll need to do so yourself (this requires a privileged session):

```
# setcap cap_net_admin+ei $(which sysctl)
# setcap cap_net_admin+ei $(which ip)
# setcap cap_net_admin+ei $(which nft)

# setcap cap_dac_override+ei $(which cgcreate)
# setcap cap_dac_override+ei $(which cgdelete)

# setcap cap_net_admin+ei $(which openvpn)
# setcap cap_net_admin+ei $(which ifconfig)

# setcap cap_net_admin+ei $(which openconnect)
```
