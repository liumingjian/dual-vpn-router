# Validation status

## Implemented and checked locally

- CLI configuration, startup, shutdown, status, and read-only diagnostics.
- Keychain integration without passwords in argv or configuration files.
- Interactive authentication input relay with hidden terminal input and separately captured cookie output.
- Background OpenConnect supervision, independent transport recovery, and interactive reauthentication state.
- Central route ownership, scoped upstream DNS routes, private-domain UDP/TCP DNS forwarding, and DNS-derived resource routes.
- Existing resolver backup/restoration, cleanup after configuration failure, and journal-based interrupted-process recovery.

Twenty-two automated tests pass, including a synthetic OpenConnect subprocess that supplies a cookie over stdin, invokes the actual configuration hook, exercises DNS-derived routing, and shuts down with temporary network state cleaned up. Network command effects are simulated; the test does not require administrator access. Static lint and formatting checks also pass.

## Deployment observations

Read-only checks established that both gateways serve an AnyConnect-style initial authentication request. Both can complete TLS handshakes under the deployment's explicitly accepted presented-certificate trust policy.

With the existing client connected to Gateway B, several representative services in Resource Set A accepted new TCP connections, and the internal business application's HTTP endpoint returned 200. This makes a single-gateway topology worth validating before assuming two sessions are necessary. It does not establish access to every host or service in either resource set.

The business application's resolved address is outside the two initially reported resource prefixes. DNS-derived host routes are therefore required in addition to prefix routing. An existing domain-specific resolver file also needs temporary takeover and restoration; the implementation supports that explicitly.

Exact endpoints, addresses, service IDs, and snapshots are retained only in Git-ignored local files.

## Not yet verified

The user completed one real gateway authentication and the CLI accepted its session metadata and saved the reusable credential. Tunnel establishment, Keychain retrieval on a subsequent login, actual privileged route/resolver changes, concurrent gateway acceptance, sleep/wake recovery, and preservation of live application connections remain unverified against the deployment.

The current agent environment has no cached administrator authorization and no VPN credentials. Local terminal execution is required to enter those values; they are not requested in chat. A local single-gateway configuration and a separate two-gateway configuration are prepared for that experiment. Until it is completed, this repository contains an implemented and locally tested controller, not a verified replacement for the deployed VPN client.

## Startup regression

The first authenticated local launch failed before a runtime directory was created, while the original client remained connected. The CLI detached the sudo subprocess into a new session before sudo could consume the terminal-scoped authorization cached by `sudo -v`. A session-aware sudo stand-in reproduces the same controller-start failure without real credentials or network changes.

The fix retains the calling session through sudo and detaches the worker from inside the privileged launcher. A startup handshake reports initialization failures, with authentication cookies redacted. Three regression checks cover authorization-context preservation, worker session separation, and sanitized initialization errors. A real privileged retry is still required to verify the deployment.
