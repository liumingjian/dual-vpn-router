# dual-vpn-router

A macOS CLI that coordinates OpenConnect VPN sessions, resource routes, and split DNS. It supports one or more gateways and replaces the AnyConnect application as the user-facing controller.

The first implementation is experimental. Automated tests exercise authentication input, the background controller, routing ownership, DNS forwarding, and recovery using local fixtures. Authenticated compatibility with a real deployment still requires local validation; passing tests does not establish that two gateways permit concurrent sessions.

## Setup

Requires macOS, [uv](https://docs.astral.sh/uv/), and [OpenConnect](https://www.infradead.org/openconnect/).

```sh
brew install openconnect
uv sync --locked
uv run dvr init
```

`init` creates `~/.config/dual-vpn-router/config.json` with mode `0600`. It asks for HTTPS gateways, explicit IPv4 resource prefixes, private DNS domains, and optional usernames. Passwords are requested at connection time. See [examples/config.json](examples/config.json) for the schema; its hosts are placeholders.

For an alternate configuration, put `--config` before the command:

```sh
uv run dvr --config /path/to/config.json doctor
uv run dvr --config /path/to/config.json up
```

Each gateway has:

- `name`, `url`, and `username`: a unique identifier, HTTPS entry point, and optional saved username.
- `routes`: explicit, non-overlapping private IPv4 prefixes owned by that gateway. Exact prefixes are required; shortened network names are not expanded automatically.
- `domains`: private DNS suffixes owned by that gateway. The longest matching suffix wins; exact duplicate domain ownership is rejected.
- `trust`: `system` for normal TLS validation, or `presented` to accept the certificate presented by this configured gateway each time interactive authentication begins. The latter is an explicit deployment trust policy, not an independently verified server identity. It does not change the system trust store.
- `keychain`: whether reusable passwords are stored in macOS Keychain; defaults to `true`. Passwords are never passed in command arguments or written to configuration.
- `dns_servers`: optional IPv4 resolver override; otherwise use resolvers supplied by the gateway.
- `replace_resolvers`: defaults to `false`. Set to `true` to temporarily replace an existing `/etc/resolver/<domain>` file, preserving its contents and metadata for restoration. Symlinks are preserved and reported as conflicts.
- `probes`: optional TCP or HTTP checks for representative internal services. These distinguish actual application access from a tunnel or route merely existing.

## Daily use

```sh
uv run dvr up
uv run dvr status
uv run dvr doctor --probe
uv run dvr down
```

`up` requests administrator authorization, authenticates through the local terminal, and starts a background controller. Passwords are read from Keychain when available; additional challenges can still be entered interactively. Closing the terminal does not stop the controller. It is not installed as a service at boot.

Authentication cookies remain in memory and cross process boundaries through pipes and a root-only local socket. Authentication output is parsed as data and never evaluated as shell code. The privileged OpenConnect processes receive cookies through stdin.

To replace a currently connected AnyConnect service during validation:

```sh
uv run dvr up --replace-anyconnect
```

This records a private network snapshot, authenticates, and then stops the original service before applying managed routes. A new authentication may itself invalidate an existing gateway session. `down` or controller failure attempts to restore the original service and verifies its connected state. If the original client needs interaction, status reports that recovery remains incomplete.

`status` reports transport/configuration state separately for each gateway. A connected tunnel does not establish application reachability; use `doctor --probe`. Gateway authentication expiry is reported as `authentication_required`; running `up` again authenticates those gateways while preserving healthy sessions.

## Routing, DNS, and recovery

The controller owns its route entries and resolver files. It does not run two unmodified `vpnc-script` instances. Existing route conflicts stop configuration rather than replacing an unrelated route.

A local UDP/TCP DNS relay forwards configured private domains through their owning tunnel. Upstream sockets bind to the tunnel interface, and resolver-address routes are scoped, allowing two tunnels to use the same DNS-server address. An unavailable gateway yields a DNS failure; the relay never forwards these names to a public resolver.

Private IPv4 addresses returned by the configured domain resolvers receive host routes through their owning tunnel before the response reaches the application, including applications outside the explicit resource prefixes. Conflicts with another gateway's configured prefix are rejected. These derived routes are retained across reconnects and removed at controller shutdown; they are not currently expired on individual DNS TTLs.

Network ownership and original resolver contents are journaled in a root-owned runtime directory. `down` can recover recorded state after an interrupted controller. Process recovery checks recorded process identity before signalling a stale PID. If a resolver has changed externally, recovery preserves that change and reports the conflict instead of overwriting it.

The first version supports IPv4 routes and IPv4 DNS upstreams. It does not configure IPv6 VPN routes, integrate with Clash, or provide automatic browser login while no user is present. Recovery requiring a new password, OTP, or browser approval is reported for interactive completion.

## Development

```sh
uv sync --locked
uv run ruff check dual_vpn_router tests
uv run ruff format --check dual_vpn_router tests
uv run python -m unittest discover -s tests -v
```

The test suite does not authenticate against company gateways, require sudo, or modify the machine's routes or resolver files. It uses temporary resolver directories, local loopback DNS sockets, a synthetic OpenConnect process, and a pseudo-terminal for the password-plus-OTP flow.

- [Design and evidence](docs/design.md)
- [Local validation plan](docs/validation-plan.md)
- [Validation status](docs/validation-status.md)
- [Domain vocabulary](GLOSSARY.md)

Deployment configuration, credentials, gateway addresses, and local diagnostic snapshots belong outside commits. `.local/` is ignored by Git.
