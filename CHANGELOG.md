<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# Changelog

All notable changes to the SSH Tunnel Manager plugin are recorded here.

## 1.0.0

Initial release.

An Open Integration Engine plugin that maintains persistent SSH tunnels from
inside the engine, so a channel can reach a vendor over an SSH tunnel without a
separate `ssh` process under systemd or an NT service. Addresses engine issue
[#357](https://github.com/OpenIntegrationEngine/engine/issues/357).

### Tunnels
- Local (`-L`) and reverse (`-R`) port forwards, kept connected for as long as a
  tunnel is enabled.
- Automatic reconnect with exponential backoff (5 seconds up to a 5-minute cap),
  re-establishing every forward after a drop.
- Tunnels start on engine start; enable, disable, and manually start or stop each
  tunnel from the Administrator.

### Authentication and host keys
- Password or private-key authentication. The key can be a file on the engine
  host or pasted into the UI, with passphrase support.
- Stored secrets are encrypted at rest and masked over the wire. A Reveal control
  fetches a stored key on demand for validation.
- Verify Key and Show Public Key derives the public key from a private key and
  confirms the passphrase, and it carries the key's own comment.
- Host-key verification: fetch the server's host key, review its fingerprint,
  accept it once, and pin connections to it. Per-tunnel opt-out with a warning.

### Monitoring
- Live status board: connection state, uptime, failed-attempt count, next-retry
  countdown, host-key status, forwards broken out by direction, and last error.
- Staged Test Connection that reports DNS, TCP reachability, host-key match,
  authentication, and per-forward reachability as separate steps.
- Per-tunnel rolling connection-event log.
- Engine events on tunnel up and down transitions, so an outage surfaces in the
  engine's Events log.

### Validation and access control
- Host and IP fields are validated up front rather than deferred to DNS.
- Local-forward bind-address collisions are rejected across tunnels, naming the
  conflicting tunnel.
- Role-based access with separate view and manage permissions.

### Compatibility
- Open Integration Engine 4.6.0
- Java 17

Licensed under MPL-2.0.
