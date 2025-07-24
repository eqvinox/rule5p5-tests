<!-- SPDX-License-Identifier: ISC -->

# RFC6724 rule 5.5 + RFC8028 test tool

## How to run

The test runs using a bridge, with an "uplink" and a "downlink" interface.

Uplink is currently expected to provide IPv4 connectivity (can be NATed),
this is for the test devices to have *some* internet connectivity so they
don't disconnect because "no internet".  IPv6 is completely filtered out
from going out on the uplink interface.

Downlink needs to be connected to test device(s), and not have any
interference from random other DHCP/DHCPv6/etc.

1. create a new network namespace
2. have 2 ethernet devices (e.g. veth, but moving physical also works) in network namespace, for uplink & downlink
3. start the runner, with --uplink and --downlink arguments
4. connect test devices & access http://192.0.2.0/ in a browser

During the IETF 123 hackathon, the setup used was another 2 bridges on the
host system outside the network namespace, one bridging the uplink to a
wired ethernet port on the IETF network, another one bridging the downlink
to a wireless access point.  IPv6 was disabled on the latter bridge.

The 192.0.2.0 IPv4 address will be "hijacked" by the bridge and should work
regardless of the IPv4 subnet in use.  The bridge also claims the 00:80:41:*
block of MAC addresses.

When using bridges, remember to turn off snooping and STP:

```
ip link set name bridge0 type bridge stp_state 0 mcast_snooping 0 mcast_vlan_snooping 0
```

The test runner does this automatically for its own bridge, but not other
bridges (like the additional two in the IETF test setup.)

## Caveats

All IPv6 packets are unicast to the test device, even IPv6 multicast.  This is
allowed by RFC6085 but may (unlikely) change some test outcome.

The tests don't currently respond to router solicitations.  None of the
devices tested sent one during the test.  (They send one initially, when
connecting to Wifi/LAN.)

Most devices will have some broken state left after tests complete, resetting
(turn off and on again) their network connection is recommended.  If you see
"unrecognized" results, this is probably the problem.
