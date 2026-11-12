# Design discovery

## Confirmed requirements

- Provide a CLI for accessing Resource Set A and Resource Set B simultaneously.
- Preserve established connections to one resource set when accessing the other.
- Provide system access for browsers, SSH, and other applications.
- Account for gateway-specific DNS requirements as well as IP routing.
- Maintain the project in its own public GitHub repository.

## Evidence and limits

A read-only snapshot of the development machine established that macOS and OpenConnect are available, an AnyConnect-named application is running, and routes for both reported destination prefixes already point to one tunnel. Scoped internal DNS resolvers are also present.

This establishes routing configuration, not end-to-end reachability. It does not establish whether either gateway can serve both resource sets, how authentication works, or whether concurrent sessions are accepted. The exact reported network prefixes are not yet confirmed as the full required resource sets.

A subsequent system status check associates that tunnel with the Cisco service named for Gateway B. The installed client is an iOS application running on macOS; no bundled CLI or AppleScript interface was found. A registered URL scheme exists, but its control capabilities remain unverified. Other network applications are running and system web and SOCKS proxies are enabled, so coexistence is a concrete design concern. Process presence alone does not establish traffic interception.

The installed network configuration script includes per-interface DNS state but also changes primary-service DNS settings on macOS. Distinct tunnel interfaces alone therefore do not establish independent DNS behavior.

OpenConnect exposes a script interface for routing and DNS configuration; its availability alone does not prove compatibility with the deployment. See the [OpenConnect manual](https://www.infradead.org/openconnect/manual.html) and [network configuration documentation](https://www.infradead.org/openconnect/vpnc-script.html).

## Decision tree

- Required behavior: simultaneous access (confirmed).
  - Application scope: system access (confirmed).
  - Supported operating systems: unresolved.
  - Coexistence with existing VPN/proxy software: unresolved.
  - Connectivity mechanism: unresolved.
    - Establish actual reachability and gateway capabilities.
    - Identify installed client controls and authentication requirements.
    - If two tunnels are needed, verify concurrent sessions and reconcile route and DNS conflicts.
    - Determine whether gateway-specific DNS answers overlap or disagree.
  - Operational behavior: unresolved.
    - Credential handling and interactive authentication.
    - Startup, reconnection, sleep/wake, and network changes.
    - Partial failure behavior and state reporting.
    - Ownership and cleanup of routes and DNS settings.

## Completion criteria for discovery

Resolve each branch using local evidence, a verified connectivity experiment, or an explicit user decision. Distinguish unverified capabilities from accepted requirements. Confirm the resulting design with the user before implementing the controller.
