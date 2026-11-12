# Dual VPN Router

Access to resources served by two VPN gateways from the same computer.

## Access

**Gateway A**:
The VPN entry point through which Resource Set A is accessible.
_Avoid_: primary gateway, default VPN

**Gateway B**:
The VPN entry point through which Resource Set B, including the internal business application, is accessible.
_Avoid_: backup gateway, fallback VPN

**Resource set**:
A collection of internal network destinations and application names accessible through a particular gateway. Membership does not imply that the two sets are disjoint.
_Avoid_: subnet, VPN

**Simultaneous access**:
Availability of both resource sets during the same period, with established connections to one set preserved while the other is used.
_Avoid_: automatic switching, failover

**System access**:
Access available to applications on the computer without configuring a separate proxy for each application.
_Avoid_: command wrapper, per-application proxy
