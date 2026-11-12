# Local compatibility validation

This is a proposed plan, not a report of a completed experiment. The user has accepted simultaneous system access, CLI-owned sessions on macOS, background operation, independent recovery, Keychain storage, and explicit trust of the configured gateways' presented certificates.

## Before changing connectivity

Record the current connected service, route ownership, relevant scoped resolver state, and representative reachable services in a Git-ignored local snapshot. Prepare recovery to the original client. Confirm that the user can tolerate interrupting the original VPN connection during the experiment; another login may cause an existing session to be replaced even before routes are changed.

Keep gateway addresses, account names, credentials, authentication cookies, and diagnostic snapshots out of commits. Collect credentials through local terminal prompts and Keychain. Treat authentication cookies as secrets and keep them out of diagnostic output.

## Experiment

1. Use the configured gateway certificate trust policy for OpenConnect, scoped to each gateway rather than system-wide trust. Handle the actual sequence of authentication challenges interactively.
2. Inspect authenticated gateway configuration using an observation hook before applying routes or resolver changes. Establish exact resource prefixes, internal DNS servers, domain scopes, and overlap. Do not infer a `/16` prefix from a shortened network name or a `/24` snapshot.
3. Verify Gateway A and Gateway B individually, then attempt concurrent sessions. Detect whether one login invalidates the other. Distinguish authentication rejection, transport failure, route conflict, DNS failure, and application rejection.
4. Reconcile route and DNS ownership centrally. Map each resource set to its verified gateway, preserve the public-network path, and give the internal business application an explicit DNS owner. Resolve shared DNS-server addresses through the intended tunnel. An unresolved ownership conflict must be reported before changing shared network state.
5. Verify representative services in both resource sets and the internal business application using system DNS and application requests. Preserve an established connection to one set while using the other. A route entry or ping alone does not establish success.
6. Exercise one-gateway failure and recovery, terminal closure, network change, sleep/wake, explicit stop, and interrupted startup. Confirm healthy access persists where required, private DNS has no public fallback, and shutdown removes only owned state.

## Outcomes

- Concurrent authenticated sessions plus application-level access establish feasibility of the dual-session topology.
- Evidence that one gateway serves both resource sets may justify a simpler topology, provided it meets the same acceptance criteria.
- Concurrent session rejection or unresolved route/DNS ownership blocks the simultaneous-access topology. Record the evidence and bring the constraint back to the user; automatic serial switching does not meet the accepted requirement.
- On experiment failure or cancellation, remove experimental state and recover the prior connection. Report any recovery step requiring user interaction rather than claiming restoration without verification.
