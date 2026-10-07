<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# SSH Tunnel Manager

An [Open Integration Engine](https://github.com/OpenIntegrationEngine/engine) plugin that gives the engine SSH tunnels it opens and keeps connected on its own, with no separate `ssh` process under systemd or an NT service. A tunnel forwards a TCP port over SSH, so the engine can reach a TCP service across a network, firewall, or NAT boundary, or be reached across one: a database inside a private VPC, an HL7/MLLP endpoint or REST/FHIR API behind a bastion, an unencrypted link carried inside SSH, or a vendor pushing into one of your channel listeners through a reverse forward.

Addresses engine issue [#357](https://github.com/OpenIntegrationEngine/engine/issues/357).

## What it does

- Keeps **local (`-L`) and reverse (`-R`) port forwards** connected for as long as a tunnel is enabled.
- **Reconnects automatically** with exponential backoff when a connection drops, re-establishing every forward.
- Manages tunnels entirely from the **Administrator Settings tab**, with no shell access to the engine host.
- Authenticates with a **password** or a **private key** (a file on the server, or a key pasted into the UI).
- Verifies the SSH server's **host key**: fetch it, see its fingerprint, accept it once, and connections are pinned to it thereafter.
- **Staged Test Connection** that reports each step (DNS, TCP reach, host-key match, authentication, and per-forward reachability) rather than one pass/fail.
- A per-tunnel **Details** view with live status (uptime, failed attempts, next-retry countdown, last error), the tunnel's forwards, and a rolling **connection-event log**.

Channels are untouched. A tunnel exposes a forwarded port; point a normal TCP Sender at a local forward, or have a vendor's reverse tunnel land on a TCP Listener.

## How it fits together

```
Local forward (-L)

  engine host                                    SSH server     target network
  channel TCP Sender ──► 127.0.0.1:6661 ══SSH══► sshd ────────► hl7.internal:6661

Reverse forward (-R)

  engine host                                      SSH server             partner network
  channel TCP Listener ◄── 127.0.0.1:6662 ◄══SSH══ 10.20.30.40:6662 ◄──── partner app
```

**The engine is the SSH client.** Every tunnel is opened by the engine process on the engine host, dialing outbound in both cases above. The Administrator only configures, starts, and monitors tunnels, so nothing is forwarded to or from the workstation running it. Four things follow:

- A local forward's bind address is the **engine host's**. `127.0.0.1:6661` is reachable by channels running in the engine, not from your workstation.
- The **engine host** needs outbound access to the SSH server. Being able to `ssh` there from your own machine says nothing about whether the engine can. Test Connection runs on the engine for this reason, so its DNS, TCP, and host-key results are the engine's view of the network.
- **Key File Path** is a path on the engine host's filesystem. If the key only exists on your workstation, paste it into the Private Key field instead.
- Tunnels belong to the engine, not to your Administrator session. They stay up after you close the Administrator or log out, and they stop when the engine stops.

A reverse forward needs no inbound firewall opening on the engine host. It does need `AllowTcpForwarding` and a non-default `GatewayPorts` in the SSH server's `sshd_config`, plus an sshd restart, since the default binds remote forwards to loopback and the application connecting to the port rarely runs on that server. Expect `GatewayPorts yes`, which forces the wildcard address and discards the one you configured, so treat a reverse forward's bind address as documentation rather than a security control. See the [Use Cases](https://github.com/diridium-com/oie-ssh-tunnel-manager/wiki/Use-Cases) wiki page for worked examples.

## Requirements

- Open Integration Engine 4.6.0
- Java 17

## Building

The plugin compiles against five engine jars. Install them once per engine version, then build:

```bash
./scripts/install-engine-jars.sh
mvn clean package
```

The script takes the jars from the published OIE release matching the POM's `mc.version`, checked against that release's `sha256sums`; CI installs the same jars from the same tarball. The installable plugin zip is written to `package/target/oie-ssh-tunnel-manager-<version>.zip`.

## Installing

Install `oie-ssh-tunnel-manager-<version>.zip` through the Administrator's Extensions page, then restart the engine. The **SSH Tunnel Manager** tab appears under Settings.

## Configuration

Each tunnel has:

- **Connection**: name, SSH host/port, username, authentication, host-key verification, and keep-alive settings.
- **Forwards**: any number of local or reverse forwards, each with a bind host/port and a destination host/port.

The settings tab is a split view. The top is the tunnel table with a color-coded status column; the bottom is a diagnostics pane that follows the selected tunnel. It auto-refreshes at the Administrator's own Dashboard refresh interval while the tab is open, and there's a **Refresh** button for an on-demand update.

**Diagnostics.**

- **Test Connection** runs a staged diagnostic and shows a per-step table: configuration checks, DNS, TCP reach to the SSH port, host-key match against the accepted key, authentication, and, per forward, whether the destination is reachable through the tunnel. A local forward's destination is probed end-to-end via a direct channel, so the test works even while the tunnel is connected. Failed and warning steps carry a hint (for example, the exact `authorized_keys` line to add when a key is rejected), with a Copy button. Run it from the edit dialog while configuring, or from the tab's Test button for a saved tunnel, where results appear in the pane.
- The **diagnostics pane** shows the selected tunnel's live status (state, uptime, failed attempts, next-retry countdown, last error), and a rolling **event log** of connects, drops, and failures with a **This tunnel / All tunnels** filter.
- **Verify Key & Show Public Key** (in the edit dialog, key auth) decrypts the private key with the passphrase, verifying it in one step, and shows the public key to add to the server's `authorized_keys`, with a Copy button.

## Security notes

- Passwords, pasted private keys, and key passphrases are **encrypted at rest** with the engine's configured encryptor. The Administrator never receives stored secrets back. It sees a mask, and sending the mask back on save keeps the stored value.
- Host-key verification is **on by default** and should stay on. Without it the tunnel is encrypted but not authenticated, so a man-in-the-middle cannot be detected. You fetch and accept a server's host key with one click before a verifying tunnel will connect. It can be disabled per tunnel, behind a warning and a persistent "Unverified" marker in the tunnel list, for lab testing.
- The browser/Administrator is not a store for secrets; see [`docs/design-notes.md`](docs/design-notes.md) for the full model.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
