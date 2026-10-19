# SSH Tunnel Manager

**Managed SSH tunnels** for Open Integration Engine: reach databases, HL7
endpoints, and APIs that sit behind SSH bastions without external tunnel
scripts. The engine owns the tunnel lifecycle — connect at startup, keep-alive,
automatic retry with backoff — and channels just connect to the local forward.

- **Local and remote forwards** — any number per tunnel, with wildcard bind
  support.
- **Password or key auth** — private keys pasted inline (stored encrypted) or
  referenced from a server-side file; passphrase support; public-key derivation
  for authorized_keys setup.
- **Host-key pinning** — fetch, review, and pin the server's host key;
  unverified keys are flagged in amber.
- **Live status** — connection state, uptime, retry countdown, and a
  per-tunnel connection event log in both administrators.
- **Connection diagnostics** — a staged test (DNS, TCP, SSH handshake, auth,
  forwards) with actionable hints, e.g. the exact authorized_keys line to add.
- **Role-based permissions** — publishes viewSshTunnels / manageSshTunnels to
  role-based authorization controllers.
- **Both administrators** — the classic Swing Administrator and the OIE web
  administrator, with full feature parity.

## Using it

- **Define** — Settings → SSH Tunnel Manager → New: endpoint, auth, host key,
  forwards.
- **Connect** — enable the tunnel; the engine keeps it up and retries on
  failure.
- **Diagnose** — Test Connection runs the staged probe with hints.

## Compatibility

Requires Open Integration Engine **4.7.0** (Java 17 or 21). Running OIE 4.6.0?
Use [1.1.0](https://github.com/diridium-com/oie-ssh-tunnel-manager/releases/tag/v1.1.0).
The web administrator UI requires an OIE web administrator and a Web Support
plugin release for OIE 4.7.0.
A restart is required after install. Safe to install with or without the web
administrator.
