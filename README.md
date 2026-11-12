# dual-vpn-router

A planned CLI for simultaneous access to multiple VPN networks with coordinated routing and split DNS.

The goal is to make resources behind two VPN gateways available to applications on the same computer, without manually switching connections or configuring each application. Existing connections to one network should continue while the other network is used. The first version targets macOS and replaces AnyConnect as the user-facing VPN controller.

This repository is in design discovery. No VPN controller has been implemented, and gateway compatibility and concurrent sessions have not been verified.

- [Design and open questions](docs/design.md)
- [Domain vocabulary](GLOSSARY.md)
- [Simultaneous system access decision](docs/adr/0001-simultaneous-system-access.md)

Examples and documentation use placeholders. Deployment addresses, DNS configuration, credentials, and diagnostic snapshots belong in local configuration. `.local/` is ignored by Git.
