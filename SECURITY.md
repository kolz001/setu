# Security Policy

setu is a privileged daemon whose whole purpose is to be a security
boundary, so vulnerability reports are especially welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: on this repository, open the **Security**
tab and choose **Report a vulnerability**. That creates a private advisory
visible only to the maintainers.

Helpful to include:

- the setu version or commit, OS and distribution
- the policy file (or a minimal one) needed to reproduce
- the exact tool calls or socket traffic, and what happened vs. what the
  policy should have allowed

You can expect an acknowledgement within a week. Fixes are developed in a
private advisory and released together with a public advisory crediting the
reporter (unless you prefer otherwise).

## Supported versions

setu is pre-1.0. Only the latest release on the default branch receives
security fixes.

## What counts as a vulnerability

In scope — anything that lets an agent connected to the broker socket do
more than its policy grants, for example:

- reaching a path outside a granted `scope.path_prefix`, or a unit/package
  outside an allowlist
- calling a tool the policy denies, or seeing one it hides
- assuming a registered agent's identity without its token
- causing a governed call to go unaudited, or corrupting / denying service
  to the audit log, snapshots, or the daemon itself
- reaching the control plane from the agent socket

Out of scope, per the [threat model](docs/architecture.md#5-security-model):
kernel exploits, side channels, and deployments where the agent keeps a raw
shell alongside setu. setu only secures anything if it is the agent's only
door to the system.

Note that unregistered agent names are self-declared: any local user who
can reach the socket can claim one. Policies that must distinguish callers
should use `require_token = true` or a `uid` pin — a rule matching an
unregistered name working as documented is not a vulnerability.
