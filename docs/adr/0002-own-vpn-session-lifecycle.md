# Own the VPN session lifecycle in the CLI

The user wants the CLI to replace AnyConnect as the way to manage company VPN access on macOS. The CLI will own VPN session establishment and lifecycle rather than depend on automating the installed AnyConnect application. OpenConnect is the proposed protocol implementation, pending gateway compatibility verification. This makes session state, routing, and DNS coordination the tool's responsibility; retaining AnyConnect as an externally controlled session owner was considered but does not provide the requested replacement.
