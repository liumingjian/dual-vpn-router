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

## Evidence and limits

A read-only snapshot of the development machine established that macOS and OpenConnect are available, an AnyConnect-named application is running, and routes for both reported destination prefixes already point to one tunnel. Scoped internal DNS resolvers are also present.

This establishes routing configuration, not end-to-end reachability. It does not establish whether either gateway can serve both resource sets, how authentication works, or whether concurrent sessions are accepted. The exact reported network prefixes are not yet confirmed as the full required resource sets.

A subsequent system status check associates that tunnel with the Cisco service named for Gateway B. The installed client is an iOS application running on macOS; no bundled CLI or AppleScript interface was found. A registered URL scheme exists, but its control capabilities remain unverified. Other network applications are running and system web and SOCKS proxies are enabled. The user has configured direct routing in Clash and does not require dedicated Clash integration. Process presence alone does not establish traffic interception.

The installed network configuration script includes per-interface DNS state but also changes primary-service DNS settings on macOS. Distinct tunnel interfaces alone therefore do not establish independent DNS behavior.

OpenConnect exposes a script interface for routing and DNS configuration; its availability alone does not prove compatibility with the deployment. See the [OpenConnect manual](https://www.infradead.org/openconnect/manual.html) and [network configuration documentation](https://www.infradead.org/openconnect/vpnc-script.html).

Anonymous HTTPS discovery failed normal certificate verification against both gateways using Python and the system curl with proxies bypassed. Handshake-only inspection found certificates issued by a private CA without a Subject Alternative Name extension. No unverified HTTP requests or authentication attempts were made, and no login form was retrieved. OpenConnect's own verification outcome has not been tested. Server identity verification therefore needs an onboarding decision before authenticated compatibility testing; a certificate fingerprint is only a trustworthy identity anchor after confirmation through an independent trusted channel.

## Decision tree

- Required behavior: simultaneous access (confirmed).
  - Application scope: system access (confirmed).
  - Supported operating systems: macOS first (confirmed).
  - Dedicated Clash integration: outside scope; existing direct rules are user-managed (confirmed).
  - Connectivity mechanism: unresolved.
    - CLI owns VPN sessions rather than automating the AnyConnect application (confirmed).
    - Establish actual reachability and gateway capabilities.
    - Verify OpenConnect compatibility and authentication requirements.
    - Decide how to establish gateway certificate trust during onboarding.
    - If two tunnels are needed, verify concurrent sessions and reconcile route and DNS conflicts.
    - Determine whether gateway-specific DNS answers overlap or disagree.
  - Operational behavior: unresolved.
    - Credential handling and interactive authentication: proposed macOS Keychain storage for reusable passwords, with interactive handling of one-time factors.
    - Startup, reconnection, sleep/wake, and network changes: proposed explicit start/stop with background operation and automatic reconnection, without launch at boot in the first version.
    - Partial failure behavior and state reporting: proposed independent recovery while the healthy resource set remains available, with no public DNS fallback for private names.
    - Ownership and cleanup of routes and DNS settings.

## Completion criteria for discovery

Resolve each branch using local evidence, a verified connectivity experiment, or an explicit user decision. Distinguish unverified capabilities from accepted requirements. Confirm the resulting design with the user before implementing the controller.
