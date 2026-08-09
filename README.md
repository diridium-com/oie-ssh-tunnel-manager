<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# SSH Tunnel Manager

An [Open Integration Engine](https://github.com/OpenIntegrationEngine/engine) plugin that gives the engine secure, self-healing SSH tunnels it manages on its own, with no separate `ssh` process under systemd or an NT service. A tunnel forwards a TCP port over SSH, so the engine can reach almost anything that speaks TCP, or be reached from almost anywhere, across network, firewall, and NAT boundaries: a database inside a private VPC, an HL7/MLLP endpoint or REST/FHIR API behind a bastion, a plaintext link you want wrapped in SSH as a VPN-lite, or a vendor pushing into one of your channel listeners through a reverse forward.

Addresses engine issue [#357](https://github.com/OpenIntegrationEngine/engine/issues/357).

## What it does

- Keeps **local (`-L`) and reverse (`-R`) port forwards** connected for as long as a tunnel is enabled.
- **Reconnects automatically** with exponential backoff when a connection drops, re-establishing every forward.
- Manages tunnels entirely from the **Administrator Settings tab** — no shell access to the engine host required.
- Authenticates with a **password** or a **private key** (a file on the server, or a key pasted into the UI).
- Verifies the SSH server's **host key**: fetch it, see its fingerprint, accept it once, and connections are pinned to it thereafter.
- **Staged Test Connection** that reports each step (DNS, TCP reach, host-key match, authentication, and per-forward reachability) rather than one pass/fail.
- A per-tunnel **Details** view with live status (uptime, failed attempts, next-retry countdown, last error), the tunnel's forwards, and a rolling **connection-event log**.

Channels are untouched. A tunnel just exposes a forwarded port; point a normal TCP Sender at a local forward, or have a vendor's reverse tunnel land on a TCP Listener.

## How it fits together

```
Local forward (-L)

  engine host                                    SSH server     target network
  channel TCP Sender ──► 127.0.0.1:6661 ══SSH══► sshd ────────► hl7.internal:6661

Reverse forward (-R)

  engine host                                      SSH server         partner network
  channel TCP Listener ◄── 127.0.0.1:6662 ◄══SSH══ 0.0.0.0:6662 ◄──── partner app
```

**The engine is the SSH client.** Every tunnel is opened by the engine process on the engine host, dialing outbound in both cases above. The Administrator only configures, starts, and monitors tunnels, so nothing is forwarded to or from the workstation running it. Four things follow:

- A local forward's bind address is the **engine host's**. `127.0.0.1:6661` is reachable by channels running in the engine, not from your workstation.
- The **engine host** needs outbound access to the SSH server. Being able to `ssh` there from your own machine says nothing about whether the engine can. Test Connection runs on the engine for this reason, so its DNS, TCP, and host-key results are the engine's view of the network.
- **Key File Path** is a path on the engine host's filesystem. If the key only exists on your workstation, paste it into the Private Key field instead.
- Tunnels belong to the engine, not to your Administrator session. They stay up after you close the Administrator or log out, and they stop when the engine stops.

A reverse forward needs no inbound firewall opening on the engine host, which is usually why it gets approved. It does normally need a non-loopback bind on the SSH server, since the application that connects to the forwarded port rarely runs on that server itself, and that requires `GatewayPorts yes` or `clientspecified` in its `sshd_config`. The default of `no` binds loopback instead of refusing, so the forward tests clean while no traffic arrives. See the [Use Cases](https://github.com/diridium-com/oie-ssh-tunnel-manager/wiki/Use-Cases) wiki page for worked examples.

## Requirements

- Open Integration Engine 4.6.0
- Java 17

## Building

The plugin compiles against five engine jars. For a local build, install them from a sibling `engine/` checkout:

```bash
ENGINE_DIR=/path/to/engine ./scripts/install-engine-jars.sh
mvn clean package
```

The installable plugin zip is written to `package/target/oie-ssh-tunnel-manager-<version>.zip`.

CI installs the same jars from the published OIE distribution tarball instead of a checkout; see `.github/workflows/build.yml`.

## Installing

Install `oie-ssh-tunnel-manager-<version>.zip` through the Administrator's Extensions page, then restart the engine. The **SSH Tunnel Manager** tab appears under Settings.

## Configuration

Each tunnel has:

- **Connection** — name, SSH host/port, username, authentication, host-key verification, and keep-alive settings.
- **Forwards** — any number of local or reverse forwards, each with a bind host/port and a destination host/port.

The settings tab is a split view. The top is the tunnel table with a color-coded status column; the bottom is a diagnostics pane that follows the selected tunnel. It auto-refreshes at the Administrator's own Dashboard refresh interval while the tab is open, and there's a **Refresh** button for an on-demand update.

**Diagnostics.**

- **Test Connection** runs a staged diagnostic and shows a per-step table: configuration checks, DNS, TCP reach to the SSH port, host-key match against the accepted key, authentication, and, per forward, whether the destination is actually reachable through the tunnel. A local forward's destination is probed end-to-end via a direct channel, so the test works even while the tunnel is connected. Failed and warning steps carry an actionable hint (for example, the exact `authorized_keys` line to add when a key is rejected), with a Copy button. Run it from the edit dialog while configuring, or from the tab's Test button for a saved tunnel (results appear in the pane).
- The **diagnostics pane** shows the selected tunnel's live status (state, uptime, failed attempts, next-retry countdown, last error), and a rolling **event log** of connects, drops, and failures with a **This tunnel / All tunnels** filter.
- **Verify Key & Show Public Key** (in the edit dialog, key auth) decrypts the private key with the passphrase — verifying it in one step — and shows the public key to add to the server's `authorized_keys`, with a Copy button.

## Security notes

- Passwords, pasted private keys, and key passphrases are **encrypted at rest** with the engine's configured encryptor. The Administrator never receives stored secrets back — it sees a mask, and sending the mask back on save keeps the stored value.
- Host-key verification is **on by default** and should stay on. Without it the tunnel is encrypted but not authenticated, so a man-in-the-middle cannot be detected — for a PHI transport that is a transmission-security failure, not a nicety. You fetch and accept a server's host key with one click before a verifying tunnel will connect. It can be disabled per tunnel, behind a firm warning and a persistent "Unverified" marker in the tunnel list, for throwaway lab testing only.
- The browser/Administrator is not a store for secrets; see [`docs/design-notes.md`](docs/design-notes.md) for the full model.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
