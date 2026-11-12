# dual-vpn-router

A macOS CLI for company VPN access through OpenConnect. It manages VPN sessions, resource routes, and private DNS so browsers, SSH, and other applications can access internal services without separate proxy configuration.

This guide covers installation from source and configuration with your own account. The tested environment is an Apple Silicon Mac. Windows and Linux are not supported. Live checks verified simultaneous access to representative services in two resource sets through one gateway. Two concurrent gateway sessions, real sleep/wake recovery, and crash recovery remain unverified. See [validation status](docs/validation-status.md).

## 1. Install from the repository

You need a Mac account that can use `sudo`, Git, and [Homebrew](https://brew.sh/). Run these commands as your normal macOS user. The CLI requests administrator authorization when it needs to change networking.

```sh
brew install uv openconnect

git clone https://github.com/liumingjian/dual-vpn-router.git
cd dual-vpn-router

uv sync --locked
uv tool install --editable .
export PATH="$HOME/.local/bin:$PATH"

dvr --help
```

This is a Python CLI; there is no separate native compilation step. `uv sync` creates the project `.venv` and installs the project from source. `uv tool install` creates an isolated user-level environment and installs the `dvr` command. You do not need to install Python packages globally.

To make `dvr` available in future terminal sessions:

```sh
uv tool update-shell
```

Restart your terminal after that command. Keep the cloned repository at the same location because the installation is editable. OpenConnect is installed separately by Homebrew and must remain available on `PATH`.

## 2. Configure your own account

The default configuration is `~/.config/dual-vpn-router/config.json`. It contains gateway addresses, routing rules, DNS domains, and usernames. Passwords belong in macOS Keychain, not in this JSON file.

Choose the setup method that matches your situation.

### Use a configuration shared by your team

Users of the same company VPN can share the gateway, route, and DNS settings. Ask the maintainer for an account-free `team-config.json` through your internal sharing channel. Company-specific addresses and deployment files are not committed to this public repository.

If you do not already have a configuration:

```sh
mkdir -p ~/.config/dual-vpn-router
cp -n /path/to/team-config.json ~/.config/dual-vpn-router/config.json
chmod 600 ~/.config/dual-vpn-router/config.json
nano ~/.config/dual-vpn-router/config.json
```

Replace each gateway's empty `username` with your own VPN username. Keep the shared gateway, route, and DNS values. Save the file, then continue to the connection step. `cp -n` preserves an existing configuration; edit that file instead if you have already set one up.

Each user authenticates with their own account and stores their password in their own macOS Keychain. Sharing this repository or an account-free configuration does not share another user's password or VPN session.

### Configure a new deployment

From the cloned repository, copy the appropriate example:

```sh
mkdir -p ~/.config/dual-vpn-router
cp -n examples/config.single.json ~/.config/dual-vpn-router/config.json
chmod 600 ~/.config/dual-vpn-router/config.json
nano ~/.config/dual-vpn-router/config.json
```

The example uses placeholder addresses. Replace `url`, `username`, `routes`, `domains`, and `probes` with values for your deployment before connecting. Use [examples/config.single.json](examples/config.single.json) when one gateway serves both resource sets. Use [examples/config.json](examples/config.json) as a two-gateway template if each gateway serves different resources. Start with one gateway when it already provides the access you need.

You can also run `dvr init` to create a configuration interactively. Its wizard asks for two gateways, their resource prefixes, DNS domains, and usernames. It refuses to overwrite an existing configuration. Passwords are requested later, when you connect.

### Configuration fields

| Field | Meaning |
| --- | --- |
| `name` | A unique lowercase gateway identifier, such as `company`. |
| `url` | The HTTPS VPN entry point, including its port if needed. Use `https://`, even if an existing client displays a bare hostname or an HTTP address. |
| `username` | Your own VPN account. If empty, the CLI asks at each authentication. |
| `routes` | Explicit private IPv4 prefixes owned by this gateway. Prefixes must not overlap, including across gateways. Use the exact prefixes supplied by your administrator; shortened network names are not expanded automatically. |
| `domains` | Private DNS suffixes owned by this gateway. An exact application hostname is also valid. The longest suffix wins; duplicate ownership is rejected. |
| `trust` | `system` uses normal TLS verification. `presented` explicitly accepts the certificate offered by this configured gateway at authentication time. It does not verify identity against an independent source or change the system trust store. |
| `keychain` | Defaults to `true`. Store and retrieve reusable passwords in this user's macOS Keychain. Set to `false` to let OpenConnect prompt each time. |
| `dns_servers` | Optional IPv4 resolver addresses. If omitted, use the DNS servers supplied by the VPN gateway. |
| `replace_resolvers` | Defaults to `false`. Set to `true` to back up, temporarily replace, and later restore an existing `/etc/resolver/<domain>` file. Symlinks remain conflicts. |
| `probes` | Representative internal services to check. A TCP probe needs `kind`, `host`, and `port`; an HTTP probe needs `kind` and `url`. See the examples. |

To use a different file, put `--config` before the command:

```sh
dvr --config /path/to/config.json up
dvr --config /path/to/config.json doctor --probe
```

## 3. Connect and verify

```sh
dvr up --replace-anyconnect
dvr status
dvr doctor --probe
```

`up` asks for administrator authorization and authenticates with your VPN account. The macOS `Password:` prompt is for your Mac login password. The gateway password prompt is for your VPN password. Password input is hidden. Complete any additional one-time-code or browser challenge when prompted.

After a successful login, the CLI saves your reusable VPN password in Keychain when `keychain` is enabled. Later connections retrieve it using your configured username; additional authentication challenges may still require interaction.

`--replace-anyconnect` allows the CLI to stop an already connected AnyConnect service before taking over its routes. If no AnyConnect service is connected, the same command still works. The CLI records a private network snapshot first. A new login may itself invalidate an existing gateway session before routing changes begin.

A successful startup message means the background controller is running. Check that each required gateway reaches `connected` in `dvr status`, then check the actual services with `dvr doctor --probe`. The diagnostic command reports failure when no representative service probes are configured, because tunnel state alone does not establish application access.

The controller keeps running when you close the terminal. It does not start automatically at boot. Passwords and authentication cookies do not appear in configuration or process arguments. Cookies remain in memory and are transferred through pipes and a root-only local socket.

## 4. Daily commands

| Command | Action |
| --- | --- |
| `dvr up --replace-anyconnect` | Connect or resume gateways that require authentication. |
| `dvr status` | Show controller, gateway, route, and DNS state. |
| `dvr doctor --probe` | Check configured gateways and representative internal services without changing network settings. |
| `dvr down` | Stop managed sessions, remove owned routes, and restore resolver files. |

If startup replaced an AnyConnect connection, `down` also attempts to restore that original connection. If the original client requires user interaction, the status report says recovery is incomplete.

Gateway authentication expiry is reported as `authentication_required`. Run `dvr up` in a terminal to authenticate those gateways again while preserving healthy sessions. For a cached password that has changed, update or remove the matching `dual-vpn-router:` item in Keychain Access, then retry authentication.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `dvr: command not found` | Run `export PATH="$HOME/.local/bin:$PATH"` in the current shell. Run `uv tool update-shell` and restart the terminal for future sessions. |
| OpenConnect is missing | Run `brew install openconnect` and check `command -v openconnect`. |
| Administrator authorization fails | Enter your Mac login password at the sudo prompt. Run the command as your normal user in a local interactive terminal. |
| Certificate verification fails | Check the gateway URL and the deployment's `trust` policy. Use `presented` only when your shared configuration explicitly calls for trusting the offered certificate. |
| An existing resolver owns a domain | Inspect `/etc/resolver/<domain>`. If the tool should temporarily own that domain, set that gateway's `replace_resolvers` to `true`; it saves the original for restoration. |
| A route conflict is reported | Stop the VPN or network tool that owns the conflicting route, then retry. The CLI preserves existing routes instead of replacing them. |
| Tunnel is connected but a service fails | Check that its network is in `routes` and its private hostname is in `domains`. Run `dvr doctor --probe` and inspect the individual results. |
| Controller stopped unexpectedly | Run `dvr down` to recover journaled network state, inspect any reported conflict, then reconnect. |

The implementation supports IPv4 VPN routes and IPv4 DNS upstreams. Private DNS responses can add host routes for applications outside the explicit resource prefixes. These routes last until controller shutdown and are retained across reconnects. The tool does not configure IPv6 VPN routes or manage Clash settings. Sleep/wake and crash recovery have automated coverage where noted, but have not been verified in the deployed environment.

## Update or uninstall

Stop the controller before updating the source used by its background processes:

```sh
dvr down
cd /path/to/dual-vpn-router
git pull --ff-only
uv sync --locked
uv tool install --reinstall --editable .
dvr up --replace-anyconnect
```

To uninstall the command, stop it and then remove its isolated tool environment:

```sh
dvr down
uv tool uninstall dual-vpn-router
```

Uninstalling the command preserves your configuration and Keychain entries.

## Development

```sh
uv sync --locked
uv run ruff check dual_vpn_router tests
uv run ruff format --check dual_vpn_router tests
uv run python -m unittest discover -s tests -v
```

The tests use temporary resolver directories, loopback DNS sockets, synthetic OpenConnect processes, and a pseudo-terminal for password-plus-OTP input. They do not require sudo, authenticate against company gateways, or change the machine's routes or resolver files.

- [Design and evidence](docs/design.md)
- [Local validation plan](docs/validation-plan.md)
- [Validation status](docs/validation-status.md)
- [Domain vocabulary](GLOSSARY.md)

Keep deployment configuration, credentials, gateway addresses, and diagnostic snapshots out of commits. `.local/` is ignored by Git. Maintainers sharing a team configuration should copy only the non-secret gateway, route, DNS, trust, and probe settings, and clear every `username` field first. Share that file through an internal channel rather than this public repository.
