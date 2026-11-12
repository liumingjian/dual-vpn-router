# Validation status

## Implemented and checked locally

- CLI configuration, startup, shutdown, status, and read-only diagnostics.
- Keychain integration without passwords in argv or configuration files.
- Interactive authentication input relay with hidden terminal input and separately captured cookie output.
- Background OpenConnect supervision, independent transport recovery, and interactive reauthentication state.
- Central route ownership, scoped upstream DNS routes, private-domain UDP/TCP DNS forwarding, and DNS-derived resource routes.
- Existing resolver backup/restoration, cleanup after configuration failure, and journal-based interrupted-process recovery.

Twenty-four automated tests pass, including a synthetic OpenConnect subprocess that supplies a cookie over stdin, invokes the actual configuration hook, exercises DNS-derived routing, and shuts down with temporary network state cleaned up. Network command effects are simulated; the test does not require administrator access. Static lint and formatting checks also pass.

## Deployment observations

Read-only checks established that both gateways serve an AnyConnect-style initial authentication request. Both can complete TLS handshakes under the deployment's explicitly accepted presented-certificate trust policy.

With the existing client connected to Gateway B, several representative services in Resource Set A accepted new TCP connections, and the internal business application's HTTP endpoint returned 200. This makes a single-gateway topology worth validating before assuming two sessions are necessary. It does not establish access to every host or service in either resource set.

The business application's resolved address is outside the two initially reported resource prefixes. DNS-derived host routes are therefore required in addition to prefix routing. An existing domain-specific resolver file also needs temporary takeover and restoration; the implementation supports that explicitly.

Exact endpoints, addresses, service IDs, and snapshots are retained only in Git-ignored local files.

## Live single-gateway validation

A subsequent local retry successfully retrieved the password from Keychain, authenticated, started the privileged controller, disconnected the original AnyConnect service, and established an OpenConnect tunnel through Gateway B.

Verified with the original client disconnected:

- Explicit routes for both requested IPv4 resource prefixes use the managed tunnel.
- Representative Resource Set A TCP services accept new connections.
- A DNS server in Resource Set B answers the internal business application query over both UDP and TCP.
- The system resolver resolves the internal business application, and its HTTP endpoint returns 200.
- The relay installs the application's derived IPv4 host route through the managed tunnel.
- An SSH connection to Resource Set A remains usable for key exchange after accessing the business application on the same running connection.
- The public Internet route remains on the existing physical interface.
- The installed user CLI reads its default private configuration and `doctor --probe` returns success without a terminal sudo cache while the privileged controller is running.

These checks establish simultaneous access for the representative services using one gateway; two concurrent gateways are unnecessary for the currently verified scope. Exact endpoint details remain in Git-ignored local evidence. The CLI is installed in an isolated uv tool environment, with a private default configuration and no credentials in the public repository.

## Not yet verified

Real shutdown/restoration, crash recovery, network-change and sleep/wake recovery, and simultaneous authentication to two gateways remain untested against the deployment. Automated coverage exercises those ownership and lifecycle paths with fixtures where noted. Successful checks do not establish availability of every host or service in either prefix.

## Startup regression

The first authenticated local launch failed before a runtime directory was created, while the original client remained connected. The CLI detached the sudo subprocess into a new session before sudo could consume the terminal-scoped authorization cached by `sudo -v`. A session-aware sudo stand-in reproduces the same controller-start failure without real credentials or network changes.

The fix retains the calling session through sudo and detaches the worker from inside the privileged launcher. A startup handshake reports initialization failures, with authentication cookies redacted. Three regression checks cover authorization-context preservation, worker session separation, and sanitized initialization errors. The subsequent real privileged retry succeeded; see the live single-gateway checks above.
