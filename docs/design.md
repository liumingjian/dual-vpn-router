# Design discovery

## Confirmed requirements

- Provide a CLI for accessing Resource Set A and Resource Set B simultaneously.
- Preserve established connections to one resource set when accessing the other.
- Provide system access for browsers, SSH, and other applications.
- Account for gateway-specific DNS requirements as well as IP routing.
- Maintain the project in its own public GitHub repository.
- Target macOS for the first version.
- Replace the AnyConnect application as the user-facing way to establish and manage company VPN access. OpenConnect is the proposed protocol implementation, subject to gateway compatibility verification.
- Existing Clash direct rules are handled by the user; dedicated Clash integration is outside the first-version scope.
- Run in the background after explicit startup, keep running when the terminal closes, and reconnect after network changes or sleep/wake. Automatic launch at boot is outside the first-version scope.
- Recover each gateway independently: keep a healthy resource set available when the other gateway fails. Private DNS queries must not fall back to public resolvers during failure.
- Store reusable passwords in macOS Keychain and request one-time factors or browser confirmation interactively when needed.
- Trust certificates presented by the explicitly configured gateways, without manual fingerprint verification or company IT approval. Scope this policy to those gateway connections rather than changing system certificate trust.

## Evidence and limits

A read-only snapshot of the development machine established that macOS and OpenConnect are available, an AnyConnect-named application is running, and routes for both reported destination prefixes already point to one tunnel. Scoped internal DNS resolvers are also present.

This establishes routing configuration, not end-to-end reachability. It does not establish whether either gateway can serve both resource sets, how authentication works, or whether concurrent sessions are accepted. The exact reported network prefixes are not yet confirmed as the full required resource sets.

A subsequent system status check associates that tunnel with the Cisco service named for Gateway B. The installed client is an iOS application running on macOS; no bundled CLI or AppleScript interface was found. A registered URL scheme exists, but its control capabilities remain unverified. Other network applications are running and system web and SOCKS proxies are enabled. The user has configured direct routing in Clash and does not require dedicated Clash integration. Process presence alone does not establish traffic interception.

The installed network configuration script includes per-interface DNS state but also changes primary-service DNS settings on macOS. Distinct tunnel interfaces alone therefore do not establish independent DNS behavior.

OpenConnect exposes a script interface for routing and DNS configuration; its availability alone does not prove compatibility with the deployment. See the [OpenConnect manual](https://www.infradead.org/openconnect/manual.html) and [network configuration documentation](https://www.infradead.org/openconnect/vpnc-script.html).

Anonymous HTTPS discovery initially failed normal certificate verification against both gateways using Python and the system curl with proxies bypassed. Handshake-only inspection found certificates issued by a private CA without a Subject Alternative Name extension. The user subsequently selected explicit trust of presented certificates for the configured gateways, without manual fingerprint verification. This permits anonymous entry-page discovery under that trust policy. Authenticated OpenConnect compatibility remains unverified. This policy accepts the presented certificate; it does not establish an independently verified gateway identity.

Under that accepted policy, anonymous requests to both gateway roots returned HTTP 200 and AnyConnect-style `config-auth` XML requesting a username. No redirects or initial password, OTP, authentication-group, or SSO fields were observed. Later authentication stages remain unknown; no form submission or authenticated session has been attempted.

## Decision tree

- Required behavior: simultaneous access (confirmed).
  - Application scope: system access (confirmed).
  - Supported operating systems: macOS first (confirmed).
  - Dedicated Clash integration: outside scope; existing direct rules are user-managed (confirmed).
  - Connectivity mechanism: unresolved.
    - CLI owns VPN sessions rather than automating the AnyConnect application (confirmed).
    - Establish actual reachability and gateway capabilities.
    - Verify OpenConnect compatibility and authentication requirements.
    - Trust presented certificates for explicitly configured gateways without manual verification (confirmed).
    - If two tunnels are needed, verify concurrent sessions and reconcile route and DNS conflicts.
    - Determine whether gateway-specific DNS answers overlap or disagree.
  - Operational behavior:
    - Credential handling and interactive authentication: macOS Keychain storage for reusable passwords, with interactive handling of one-time factors (confirmed).
    - Startup, reconnection, sleep/wake, and network changes: explicit start/stop with background operation and automatic reconnection, without launch at boot in the first version (confirmed).
    - Partial failure behavior and state reporting: independent recovery while the healthy resource set remains available, with no public DNS fallback for private names (confirmed).
    - Ownership and cleanup of routes and DNS settings: proposed central controller with explicit ownership records; remove only tool-owned state and preserve unrelated settings.

## Proposed command surface

- `init`: configure gateways and resource ownership locally; store credentials through Keychain when supplied interactively.
- `up`: authenticate as needed, establish the required sessions, and start background management.
- `down`: stop managed sessions and remove network state owned by this tool.
- `status`: report gateway connection, routing, DNS, and authentication-required states separately.
- `doctor`: inspect configuration and report connectivity or configuration failures without silently changing network state.

## Validation before selecting the final tunnel topology

Authentication must take place locally; passwords and one-time factors are not collected in chat or public repository files. Establish whether the same credentials can maintain both gateway sessions concurrently. Observe actual gateway-provided addresses, routes, resolvers, and domains rather than treating the current route snapshot as authoritative configuration.

Validate the internal business application using the system resolver and an HTTP request, and validate representative services in each resource set. A route entry or successful ping alone is insufficient. Check that access to one set preserves an established connection to the other. If concurrency is rejected, report the unmet requirement; automatic serial switching is outside the accepted product boundary.

Overlapping resource prefixes, conflicting DNS answers, and gateway-provided DNS addresses shared across tunnels require explicit ownership in local configuration. A network controller must coordinate these resources rather than run two unchanged copies of the default configuration script. The exact ownership rules remain a validation prerequisite.

The [local validation plan](validation-plan.md) defines the proposed experiment and its completion criteria. Its execution and the final design await the user's shared-understanding confirmation.

## Completion criteria for discovery

Resolve each branch using local evidence, a verified connectivity experiment, or an explicit user decision. Distinguish unverified capabilities from accepted requirements. Confirm the resulting design with the user before implementing the controller.
