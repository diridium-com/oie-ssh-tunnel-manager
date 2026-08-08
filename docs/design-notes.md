<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# Design notes

Why the code is shaped the way it is. Written for someone reading or reviewing the repo, not as a change log.

_Last reviewed: 2026-08-08._

## Why a service plugin, not a connector

Issue #357 asks for tunnels that the engine keeps alive, replacing external `ssh` processes. A destination connector would only cover outbound traffic on a per-message basis and would not address reverse tunnels for inbound vendor traffic. A background service that maintains long-lived tunnels, with channels using ordinary TCP connectors against the forwarded ports, matches what operators actually run today. So the plugin is a `ServicePlugin` with a settings panel, not a new connector type.

## Why JSch (the mwiede fork)

The engine already ships `com.github.mwiede:jsch` in `server-lib` and uses it for the SFTP connector, so we depend on it at `provided` scope and bundle no SSH library. That single fact drove the choice, but it was not assumed — Apache MINA SSHD was evaluated as the main alternative, including a runnable probe of both libraries against an in-JVM SSH server on the engine's pinned dependency versions.

What the evaluation found:

- Both libraries do everything v1 needs: password and public-key auth, local and reverse forwards, and every private-key format an admin might paste (OpenSSH new format with and without a passphrase, PKCS#8, legacy PEM), with ed25519 working on Java 17 without an extra crypto dependency.
- MINA has the nicer API (event-driven disconnect notification, structured errors, a returned server-assigned port for `-R :0`). JSch is poll-based and stringly-typed by comparison.
- MINA would be a bundled jar on a flat plugin classpath, and we would own its CVE watch and the pending 3.0 API migration. JSch is patched by the engine.

The deciding factor was ownership and blast radius, not capability. JSch's real weaknesses are ones we compensate for in a small amount of our own code (see reconnection below), and its forwarding path has the quieter bug history of the two. If a future requirement needs the engine to *accept* inbound SSH (an embedded SSH server), JSch cannot do that and the decision should be revisited — MINA would be the only option then.

To keep that option cheap, all JSch use sits behind a `SshConnection` / `SshConnectionFactory` seam. Swapping the SSH library means writing one new factory; nothing else changes, and the manager's tests run against a fake and never open a socket.

## Reconnection is our job, and why the reconciler looks the way it does

JSch has two behaviors we design around, both verified against the source:

1. **No disconnect callback.** There is no listener; you learn a session died by polling `isConnected()`. So a single reconciler thread wakes on a fixed interval, checks each tunnel, and reconnects the dead ones.
2. **Forwards do not survive a reconnect.** `Session.disconnect()` deletes every forward registration, and JSch has no auto-reconnect. So reconnecting always re-establishes all of a tunnel's forwards from the stored config, rather than trying to preserve them.

The reconciler owns all tunnel state on one thread; every mutation (config apply, manual start/stop, shutdown) is posted as a task to that thread, so there are no locks. Status for the UI is published as a volatile immutable snapshot. Reconnect uses exponential backoff capped at five minutes so a permanently misconfigured tunnel does not hammer a server.

`setServerAliveInterval` in JSch also sets the socket read timeout, not only the keep-alive cadence. That coupling is deliberate in our config (a keep-alive interval doubles as a liveness timeout) and is called out in the code so nobody "fixes" it later.

## Secret handling

Three fields are secret: the password, a pasted private key, and a key passphrase. They are handled in one place (`SecretFields`) with three rules:

- **At rest:** encrypted with the engine's configured encryptor and stored with an `{enc}` marker so decryption can tell an encrypted value from a legacy plaintext one. The in-memory list always holds plaintext (load decrypts, edits pass through verbatim), so the encrypt step always encrypts — it does not treat a secret that happens to start with `{enc}` as already-ciphertext, which would otherwise persist it in the clear.
- **On the wire to the client:** replaced with a mask. The Administrator never receives a stored secret. When the client sends the mask back on save, the stored value is kept; any other value replaces it. This is how you edit a tunnel's host without re-typing its password.
- **On decrypt failure:** the field is returned empty, not as the raw `{enc}` blob, so a failed decrypt forces a deliberate re-entry rather than silently carrying an unusable value forward.

If the stored configuration cannot be read at startup (corrupt data, a decryptor that throws), the service refuses to persist. Saving over unreadable data would destroy every stored tunnel. Management is read-only until the underlying problem is fixed, and the log says so.

## Diagnostics

Test Connection is a **staged** diagnostic, not a single pass/fail, because a single result can't tell an operator whether the problem is DNS, the network path, the host key, credentials, or one specific forward. `diagnose()` runs the stages in order — DNS resolution, TCP reach to the SSH port, host-key fetch and comparison against the accepted key, authentication, then each forward — and returns a list of steps each carrying pass/warn/fail/skip, a detail line, and a duration. The dialog renders that as a table.

The forward stage is the interesting one. A local (`-L`) forward is tested by opening a **direct-tcpip channel** to the destination through the SSH server — the exact path the forward carries — rather than by binding a local listener. That means the test verifies the destination is genuinely reachable end-to-end, and it binds no local port, so it never collides with a tunnel that is already connected. A remote (`-R`) forward can't be driven end-to-end from the engine side (the server initiates the return connection), so the test confirms the server *grants* the remote listen and then releases it; when the tunnel is already live, the remote-forward step is skipped with a note rather than fighting the live listener for the port. This replaced an earlier design that reconnected the whole tunnel and re-bound its ports, which falsely failed against any running tunnel.

Debugging state that the server already tracks — uptime, failed-attempt count, next-retry time, last error — is surfaced in a per-tunnel Details view, alongside a rolling per-tunnel event log (connects, drops, failures, config changes). The event log is a bounded concurrent deque per tunnel, written on the reconciler thread and read from servlet threads; it is in-memory only and does not survive a restart, which is the right lifetime for live debugging without turning the config store into a log sink.

## Host-key verification

Verification is on by default and enforced with a custom `HostKeyRepository` that accepts exactly one key — the one the admin fetched and explicitly accepted — and reports every other key as changed, which makes JSch refuse the connection under `StrictHostKeyChecking=yes`. The key is fetched by connecting far enough to complete key exchange (the host key is known before authentication) and then disconnecting without ever sending credentials. Verification can be turned off per tunnel for lab use; that path is guarded and warned about, not silent.

## Why persistence does not use the engine's ObjectXMLSerializer

The stored tunnel blob is server-only: the Administrator receives tunnels as JSON/XML through the servlet, never in this stored form. Routing at-rest storage through the engine's `ObjectXMLSerializer` pulled its whole converter chain (Rhino and more) onto the test classpath for no benefit. Persistence instead uses a private XStream, built with a DOM driver (no `xpp3` dependency) and locked to this plugin's own types via an explicit allowlist, so it can only ever deserialize a tunnel — not an arbitrary class from a tampered store. The engine's `ObjectXMLSerializer.allowTypes` registration is still done at startup, but only for the client-facing REST path that genuinely needs it.

## Standing results

- `mvn clean package` builds green and runs **51 tests** across the modules: the reconciler's connect/reconnect/backoff/stop-start/config-change/shutdown behavior and its event log (fake SSH factory, fake clock, fully deterministic), secret mask/encrypt/decrypt handling, service CRUD with the persist-and-reload round trip, the diagnostic result model and the service's diagnostic/event routing, the servlet-interface permission mapping, the RBAC permission publication, and a plugin.xml wiring check that loads every declared class and confirms it implements the expected engine interface.
- CI installs the engine jars from the published OIE tarball with the version single-sourced from `mc.version`, and fails the build if zero surefire reports were produced (guarding against a silently skipped suite).
- No build warnings are expected. The jarsigner step is skipped unless the `signing` profile is active.

## Review pass (2026-08-08)

A multi-agent adversarial review (concurrency/lifecycle, security, and correctness dimensions, each finding independently verified before action) surfaced nine real defects, all fixed in this repo. The load-bearing ones:

- **Startup publication order.** `init()` published the service singleton before loading stored config, leaving a narrow window where a request could persist over unread data. The instance is now published last.
- **Shutdown could leak sessions.** The close wait was shorter than a single connect timeout and a timed-out close task was silently discarded. Shutdown now sets a `closed` flag (so nothing reopens), waits longer than one connect attempt, and closes any stragglers from the caller thread after the executor terminates.
- **A secret beginning with the literal `{enc}` was persisted in the clear.** The encrypt step skipped values already carrying the marker, but in-memory secrets are always plaintext, so it now always encrypts.
- **Duplicate dropped secrets.** Duplicating a tunnel carried the masked secret strings, which resolved to empty on create; the duplicate flow now blanks them so the admin re-enters real values.
- **Test Connection failed on a running tunnel.** Re-establishing forwards collided with the live tunnel's bound ports; a test of an already-connected tunnel is now auth-only and says so.
- Plus: RejectedExecutionException from manager calls during shutdown (dropped cleanly), an over-broad XStream Collection allowlist (narrowed to the one type used), a dialog that disposed before server-only validation could run (name-uniqueness and bind-host checks moved client-side too), and an unsynchronized uniqueness scan during a test (a test never persists, so it no longer runs that check).

Nothing was accepted-rather-than-fixed.

## What the tests do not cover

- **No real SSH integration test.** Everything below `SshConnection` — the actual JSch handshake, forward establishment, host-key fetch, key parsing, and the staged `diagnose()` implementation (DNS/TCP/host-key/auth/direct-tcpip probing) — is exercised only by the standalone probe used during library selection, not by the committed suite. The committed tests drive `diagnose()` through a fake that returns canned per-step results, which covers the service and UI wiring but not the JSch-level probing itself. The committed tests deliberately never open a socket. A live end-to-end test against a container-hosted `sshd` would be the highest-value addition and is not present.
- **The Swing UI is not tested.** The dialog and settings panel have no automated coverage; validation logic is duplicated on the server (which is tested) so the untested copy is a convenience, not the enforcement point.
- **RBAC client-side task hiding is not verified here.** The plugin registers its task names, but the engine's known limitation around hiding appended task-pane items is not re-litigated by this repo.
