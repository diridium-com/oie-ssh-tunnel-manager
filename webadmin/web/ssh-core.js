// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * Framework-agnostic core for the SSH Tunnel Manager web UI: the table
 * formatters, status/host-key display rules, the event-log merge, the secret
 * mask helpers, and the tunnel validator — ported 1:1 from the Swing client's
 * TunnelTableModel / TunnelStatusCellRenderer / TunnelDiagnosticsPane /
 * SshTunnelDialog and the shared Hosts / PortForward helpers so the web
 * administrator shows byte-identical texts.
 *
 * No DOM/React here — just data, numbers, and strings. tunnel-panel.jsx /
 * tunnel-dialog.jsx / diagnostic-dialog.jsx build on top of this; it is
 * unit-testable with plain `node --test`.
 *
 * Time-dependent formatters (fmtUptime, fmtNextRetry) take an explicit nowMs
 * so callers pass one Date.now() per render tick and tests stay deterministic.
 */

/* ---- input tolerance helpers ------------------------------------------------ */

// Wire numbers can arrive as strings (XStream JSON quirk); null/undefined/NaN
// count as 0 for arithmetic.
function num(v) {
    const n = Number(v);
    return Number.isNaN(n) ? 0 : n;
}

// Trimmed-string view of a form/wire value; null/undefined read as ''.
function str(v) {
    return v == null ? '' : String(v).trim();
}

// Raw-string view (no trim) for values Swing reads verbatim (secrets, PEM text).
function raw(v) {
    return v == null ? '' : String(v);
}

// The dialogs' name for the same no-trim coercion, exported so they share it.
export const strOf = raw;

// Wire booleans arrive as the STRING 'false' (XStream quirk); null/undefined
// fall back to the model default.
function bool(v, dflt) {
    if (v == null) {
        return dflt;
    }
    return v !== false && String(v) !== 'false';
}

// XStream collection quirks: '' for an empty collection, a bare object for a
// singleton. normalizeTunnel (ssh-api.js) already unwraps these; this is the
// defensive equivalent for callers handing in raw-ish data.
export function toArray(v) {
    if (Array.isArray(v)) {
        return v;
    }
    if (v == null || v === '') {
        return [];
    }
    return [v];
}

// Integer.parseInt strictness: optional sign and digits only ("1.5", "1e3",
// "0x10" rejected), plus a JS-side safety bound — digit strings beyond
// Number.MAX_SAFE_INTEGER would be silently altered by Number().
const INT_RE = /^[+-]?\d+$/;
const parsableInt = (text) => INT_RE.test(text) && Number.isSafeInteger(Number(text));

/* ---- secret mask (SshTunnel.SECRET_MASK semantics) -------------------------- */

// The placeholder the server returns instead of a stored secret; a client
// sending it back means "keep the stored value". The canonical exported
// constant lives in ssh-api.js (the wire module); this copy stays private so
// there is exactly one contract-pinned export of it.
const SECRET_MASK = '********';

// True when a secret field still shows the server's mask (i.e. the admin has
// not retyped or revealed it). Strict: only the exact mask string counts.
export function isMasked(v) {
    return v === SECRET_MASK;
}

// Duplicate semantics (SshTunnelSettingsPanel.duplicateTunnel): the source
// tunnel came from getTunnels(), so its secrets are the mask string. Blank
// password, private key PEM, AND passphrase so the admin re-enters real
// secrets for the new tunnel. Returns a copy (forwards copied too); the panel
// additionally nulls the id and renames to "<name> (copy)".
export function blankSecrets(t) {
    const src = t || {};
    return {
        ...src,
        password: '',
        privateKeyPem: '',
        privateKeyPassphrase: '',
        forwards: toArray(src.forwards).map((f) => ({ ...(f || {}) })),
    };
}

/* ---- table formatters (TunnelTableModel, 1:1) ------------------------------- */

// TunnelTableModel.humanizeDuration: whole units, two largest shown —
// "5s", "1m 5s", "2h 2m". Negative durations clamp to "0s".
// (Companion to fmtUptime/fmtNextRetry; not in the pinned module contract.)
export function humanizeDuration(millis) {
    const seconds = Math.max(0, Math.floor(num(millis) / 1000));
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) {
        return h + 'h ' + m + 'm';
    }
    if (m > 0) {
        return m + 'm ' + s + 's';
    }
    return s + 's';
}

// TunnelTableModel.uptimeText: '' when not connected (connectedSince 0/absent);
// otherwise the humanized age of the connection. The Swing model also requires
// state == CONNECTED before showing an uptime — that gate is the CALLER's
// (the server only sets connectedSince while connected, but gate anyway for
// byte-parity on stale data).
export function fmtUptime(connectedSinceMs, nowMs) {
    const since = num(connectedSinceMs);
    if (since <= 0) {
        return '';
    }
    return humanizeDuration(num(nowMs) - since);
}

// TunnelTableModel.nextRetryText: '' when no retry is scheduled (0/absent),
// "now" when the scheduled time has passed, otherwise "in <duration>".
export function fmtNextRetry(nextRetryAtMs, nowMs) {
    const at = num(nextRetryAtMs);
    if (at <= 0) {
        return '';
    }
    const delta = at - num(nowMs);
    return delta <= 0 ? 'now' : 'in ' + humanizeDuration(delta);
}

// TunnelTableModel.forwardSummary: forwards broken out by direction,
// e.g. "2L / 1R" (local -L, remote -R). Anything not REMOTE counts as local,
// mirroring the Java else-branch.
export function forwardsSummary(forwards) {
    let local = 0;
    let remote = 0;
    for (const forward of toArray(forwards)) {
        if (forward != null && str(forward.direction) === 'REMOTE') {
            remote++;
        } else {
            local++;
        }
    }
    return local + 'L / ' + remote + 'R';
}

// SshTunnel.getEndpointDescription: "user@host:port", raw field values.
export function endpointLabel(t) {
    const tunnel = t || {};
    return raw(tunnel.username) + '@' + raw(tunnel.host) + ':'
        + (tunnel.port == null ? '' : String(tunnel.port));
}

/* ---- status & host-key display (renderer + table model, 1:1) ---------------- */

// TunnelState display names, keyed by wire enum name.
const STATE_DISPLAY = {
    CONNECTED: 'Connected',
    CONNECTING: 'Connecting',
    RECONNECTING: 'Reconnecting',
    DISCONNECTED: 'Disconnected',
    FAILED: 'Failed',
    DISABLED: 'Disabled',
};

// TunnelTableModel.statusText + TunnelStatusCellRenderer: no runtime status
// yet means Disconnected (or Disabled when the tunnel is disabled). Color ONLY
// the exception that needs attention: FAILED is red; every other state —
// Connected included — is plain, because coloring the normal cases just adds
// noise. Swing's RED is #C02828; the web panel maps the tone to its own CSS.
export function statusDisplay(t, status) {
    let key;
    if (status == null) {
        key = bool(t && t.enabled, true) ? 'DISCONNECTED' : 'DISABLED';
    } else {
        // SshTunnelStatus defaults its state to DISCONNECTED.
        key = str(status.state).toUpperCase() || 'DISCONNECTED';
    }
    return {
        text: STATE_DISPLAY[key] || str(status && status.state),
        tone: key === 'FAILED' ? 'red' : 'plain',
    };
}

// Host Key column: "Pinned" plain when verification is on, "Unverified" amber
// as a standing warning when it is off (Swing's AMBER is #B86E00).
export function hostKeyDisplay(t) {
    if (bool(t && t.verifyHostKey, true)) {
        return { text: 'Pinned', tone: 'plain' };
    }
    return { text: 'Unverified', tone: 'amber' };
}

/* ---- event log (TunnelDiagnosticsPane, 1:1) --------------------------------- */

// TunnelDiagnosticsPane's TIME_FMT: "HH:mm:ss" in the viewer's local time zone
// (Swing formats with the client JVM's ZoneId.systemDefault()).
export function fmtEventTime(ms) {
    return new Date(num(ms)).toTimeString().slice(0, 8);
}

// TunnelDiagnosticsPane.refreshEvents: flattens per-tunnel event lists into
// display rows, newest-first (stable for equal timestamps, like Java's stable
// sort). perTunnelLists is an array of { tunnelId, tunnelName, events }
// entries; a missing tunnelName falls back to the id (Swing's
// names.getOrDefault(id, id)). filterTunnelId null = "All tunnels"; a tunnel
// id = "This tunnel" (ids compared String()-coerced). "This tunnel" with no
// selection is the PANEL's concern — it passes no entries or a null filter as
// appropriate.
export function mergeEvents(perTunnelLists, filterTunnelId) {
    const filter = filterTunnelId == null ? null : String(filterTunnelId);
    const rows = [];
    for (const entry of toArray(perTunnelLists)) {
        if (entry == null) {
            continue;
        }
        const id = entry.tunnelId == null ? null : String(entry.tunnelId);
        if (filter != null && id !== filter) {
            continue;
        }
        const name = entry.tunnelName != null ? String(entry.tunnelName) : (id == null ? '' : id);
        for (const event of toArray(entry.events)) {
            if (event == null) {
                continue;
            }
            rows.push({
                tunnelId: id,
                tunnelName: name,
                timestamp: num(event.timestamp),
                // TunnelEvent defaults its level to INFO.
                level: str(event.level) || 'INFO',
                message: raw(event.message),
            });
        }
    }
    rows.sort((a, b) => b.timestamp - a.timestamp);
    return rows;
}

/* ---- host syntax (shared Hosts helper, 1:1) --------------------------------- */

// Hosts.validationError: null when host is a valid IPv4, IPv6, or hostname;
// otherwise a human-readable message prefixed with label. Catches obvious
// garbage up front (out-of-range IPv4 octets, illegal hostname characters)
// rather than letting DNS reject it at connect time. allowWildcard accepts a
// bare '*' — valid for a forward BIND host meaning "all local interfaces",
// never for an SSH host or a forward destination. Messages carry NO trailing
// period; validateTunnel appends '.' exactly as SshTunnelDialog does.
// (Companion export for live per-field checks; not in the pinned contract.)
export function hostValidationError(label, host, allowWildcard) {
    if (host == null || String(host).trim() === '') {
        return label + ' is required';
    }
    const h = String(host).trim();

    if (allowWildcard && h === '*') {
        return null;
    }

    if (h.indexOf(':') >= 0) {
        return isPlausibleIpv6(h) ? null : label + " '" + host + "' is not a valid IPv6 address";
    }

    const parts = h.split('.');
    // Four all-numeric parts is an IPv4 attempt — validate it strictly rather
    // than fall through to hostname rules and ship a bad octet off to DNS.
    if (parts.length === 4 && parts.every(isAllDigits)) {
        for (const part of parts) {
            if (!isOctet(part)) {
                return label + " '" + host + "' is not a valid IP address (each octet must be 0-255)";
            }
        }
        return null;
    }

    return isValidHostname(h) ? null : label + " '" + host + "' is not a valid hostname or IP address";
}

function isAllDigits(part) {
    return part.length > 0 && /^[0-9]+$/.test(part);
}

function isOctet(part) {
    // Already all digits; mirror Java's length cap then range check.
    return part.length >= 1 && part.length <= 3 && Number(part) <= 255;
}

function isValidHostname(host) {
    const h = host.endsWith('.') ? host.substring(0, host.length - 1) : host; // trailing dot = FQDN
    if (h === '' || h.length > 253) {
        return false;
    }
    for (const label of h.split('.')) {
        if (label === '' || label.length > 63 || label.startsWith('-') || label.endsWith('-')) {
            return false;
        }
        if (!/^[A-Za-z0-9_-]+$/.test(label)) {
            return false;
        }
    }
    return true;
}

function isPlausibleIpv6(host) {
    let addr = host;
    const zone = addr.indexOf('%'); // scope/zone id, e.g. fe80::1%eth0
    if (zone >= 0) {
        addr = addr.substring(0, zone);
    }
    let colons = 0;
    for (const c of addr) {
        const hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!(hex || c === ':' || c === '.')) {
            return false;
        }
        if (c === ':') {
            colons++;
        }
    }
    return colons >= 2 && colons <= 7;
}

/* ---- local bind collisions (PortForward.localBindCollidesWith, 1:1) --------- */

// A wildcard bind (empty, 0.0.0.0, ::, or *) overlaps any host; localhost is
// an alias for 127.0.0.1. Two LOCAL forwards whose bind address overlaps on
// the same port can never both listen at once.
function normalizeBindHost(host) {
    if (host == null) {
        return '*';
    }
    const h = String(host).trim().toLowerCase();
    if (h === '' || h === '0.0.0.0' || h === '::' || h === '*') {
        return '*';
    }
    if (h === 'localhost') {
        return '127.0.0.1';
    }
    return h;
}

function localBindCollides(a, b) {
    if (str(a.direction) !== 'LOCAL' || str(b.direction) !== 'LOCAL') {
        return false;
    }
    if (num(a.bindPort) !== num(b.bindPort)) {
        return false;
    }
    const na = normalizeBindHost(a.bindHost);
    const nb = normalizeBindHost(b.bindHost);
    return na === '*' || nb === '*' || na === nb;
}

/* ---- tunnel validation (SshTunnelDialog.validateLocally, 1:1) --------------- */

// The web-only integer-range checks (Swing's spinners clamp, so these have no
// Swing message): blank takes the model default, anything unparseable or out
// of range pushes the given message and falls back to the default.
function rangeInt(v, dflt, min, max, field, message, errors) {
    const text = str(v);
    if (text === '') {
        return dflt;
    }
    if (parsableInt(text) && Number(text) >= min && Number(text) <= max) {
        return Number(text);
    }
    errors.push({ field, message });
    return dflt;
}

// ForwardTableModel.parsePort: blank or unparseable reads as 0, which then
// fails the 1-65535 range check with the same message Swing would show.
function parsePort(value) {
    if (value == null) {
        return 0;
    }
    const text = String(value).trim();
    if (text === '' || !parsableInt(text)) {
        return 0;
    }
    return Number(text);
}

// Swing shows one JOptionPane per problem and stops at the first; here every
// problem is collected in the dialog's field order, so errors[0] is exactly
// what Swing would have shown first. Messages are verbatim (host messages get
// the trailing '.' the dialog appends).
//
// allTunnels is the FULL tunnel list from getTunnels(); the tunnel under edit
// is excluded by id (String()-coerced), so a new/duplicated tunnel (id null)
// checks against every existing tunnel — exactly Swing's otherNames /
// otherLocalForwards construction. Covered: required unique name
// (case-insensitive), host syntax, SSH port range, required username, the
// auth-mode secret (a masked value counts as present = keep stored), host key
// accepted when verification is on, keep-alive spinner ranges, per-forward
// direction/host/port checks (wildcard allowed only for bind hosts), and
// duplicate local binds both within the tunnel and against every other
// tunnel's local forwards (wildcard-aware, naming the conflicting tunnel).
//
// Checks Swing's widgets made impossible (SSH port range, keep-alive ranges,
// forward direction) use this module's own messages; everything else is
// byte-identical to validateLocally.
//
// The returned value is the normalized tunnel in model declaration order:
// strings trimmed exactly where Swing's collectInto trims (password,
// passphrase, and the PEM text deliberately raw), numbers as numbers with the
// model defaults for blanks (port 22, keep-alive 30/3), booleans real
// booleans, id String()-coerced or null, forwards reduced to the five
// PortForward fields. Only meaningful when errors is empty.
export function validateTunnel(t, allTunnels) {
    const tunnel = t || {};
    const errors = [];

    const selfId = tunnel.id == null ? null : String(tunnel.id);
    const others = toArray(allTunnels).filter((o) => o != null
        && !(selfId != null && o.id != null && String(o.id) === selfId));

    const name = str(tunnel.name);
    if (name === '') {
        errors.push({ field: 'name', message: 'Name is required.' });
    } else {
        const lower = name.toLowerCase();
        if (others.some((o) => str(o.name).toLowerCase() === lower)) {
            errors.push({ field: 'name', message: "A tunnel named '" + name + "' already exists." });
        }
    }

    const hostError = hostValidationError('SSH host', raw(tunnel.host), false);
    if (hostError != null) {
        errors.push({ field: 'host', message: hostError + '.' });
    }

    // Swing's JSpinner clamps to 1-65535, so this check has no Swing message.
    const port = rangeInt(tunnel.port, 22, 1, 65535, 'port',
        'SSH port must be between 1 and 65535.', errors);

    if (str(tunnel.username) === '') {
        errors.push({ field: 'username', message: 'Username is required.' });
    }

    // Wire enum names; anything but PRIVATE_KEY reads as PASSWORD (the model
    // default), and anything but INLINE reads as FILE.
    const authMethod = str(tunnel.authMethod) === 'PRIVATE_KEY' ? 'PRIVATE_KEY' : 'PASSWORD';
    const keySource = str(tunnel.keySource) === 'INLINE' ? 'INLINE' : 'FILE';
    const password = raw(tunnel.password);
    const privateKeyPem = raw(tunnel.privateKeyPem);
    if (authMethod === 'PASSWORD') {
        // Raw length like Swing's getPassword().length — never trimmed, and
        // the mask counts as present (keep the stored password).
        if (password.length === 0) {
            errors.push({ field: 'password', message: 'Password is required for password authentication.' });
        }
    } else if (keySource === 'FILE') {
        if (str(tunnel.privateKeyPath) === '') {
            errors.push({ field: 'privateKeyPath', message: 'Private key path is required.' });
        }
    } else if (privateKeyPem.trim() === '') {
        errors.push({ field: 'privateKeyPem', message: 'Private key is required.' });
    }

    const verifyHostKey = bool(tunnel.verifyHostKey, true);
    const acceptedHostKey = raw(tunnel.acceptedHostKey);
    if (verifyHostKey && acceptedHostKey === '') {
        errors.push({
            field: 'acceptedHostKey',
            message: 'Host key verification is enabled but no host key has been accepted.'
                + ' Fetch and accept the host key, or turn off verification.',
        });
    }

    // Swing's spinners clamp to 0-3600 and 1-20, so these have no Swing message.
    const serverAliveIntervalSeconds = rangeInt(tunnel.serverAliveIntervalSeconds, 30, 0, 3600,
        'serverAliveIntervalSeconds', 'Keep-alive (sec) must be between 0 and 3600.', errors);
    const serverAliveCountMax = rangeInt(tunnel.serverAliveCountMax, 3, 1, 20,
        'serverAliveCountMax', 'Keep-alive retries must be between 1 and 20.', errors);

    // Forwards, normalized the way ForwardTableModel stores edits: hosts
    // trimmed, ports parsed (unparseable -> 0), direction defaulting LOCAL.
    const forwards = toArray(tunnel.forwards).map((f) => {
        const fw = f || {};
        return {
            direction: str(fw.direction) === '' ? 'LOCAL' : str(fw.direction),
            bindHost: str(fw.bindHost),
            bindPort: parsePort(fw.bindPort),
            destinationHost: str(fw.destinationHost),
            destinationPort: parsePort(fw.destinationPort),
        };
    });

    forwards.forEach((forward, i) => {
        const at = 'forwards[' + i + '].';
        // Swing's direction combo makes an invalid direction impossible.
        if (forward.direction !== 'LOCAL' && forward.direction !== 'REMOTE') {
            errors.push({ field: at + 'direction', message: 'Every forward needs a direction (Local or Remote).' });
        }
        const bindError = hostValidationError('Forward bind host', forward.bindHost, true);
        if (bindError != null) {
            errors.push({ field: at + 'bindHost', message: bindError + '.' });
        }
        if (forward.bindPort < 1 || forward.bindPort > 65535) {
            errors.push({ field: at + 'bindPort', message: 'Every forward needs a bind port between 1 and 65535.' });
        }
        const destError = hostValidationError('Forward destination host', forward.destinationHost, false);
        if (destError != null) {
            errors.push({ field: at + 'destinationHost', message: destError + '.' });
        }
        if (forward.destinationPort < 1 || forward.destinationPort > 65535) {
            errors.push({ field: at + 'destinationPort', message: 'Every forward needs a destination port between 1 and 65535.' });
        }
    });

    const locals = forwards.filter((f) => f.direction === 'LOCAL');
    for (let i = 0; i < locals.length; i++) {
        for (let j = i + 1; j < locals.length; j++) {
            if (localBindCollides(locals[i], locals[j])) {
                errors.push({
                    field: 'forwards',
                    message: 'Two local forwards bind the same address ('
                        + locals[i].bindHost + ':' + locals[i].bindPort + ').',
                });
            }
        }
    }

    // Every other tunnel's LOCAL forwards, tagged with the owning tunnel's
    // name — Swing's NamedForward — so a collision names the offender.
    const otherLocalForwards = [];
    for (const other of others) {
        for (const f of toArray(other.forwards)) {
            const fw = f || {};
            if (str(fw.direction) === 'LOCAL') {
                otherLocalForwards.push({
                    tunnelName: str(other.name),
                    forward: {
                        direction: 'LOCAL',
                        bindHost: str(fw.bindHost),
                        bindPort: parsePort(fw.bindPort),
                    },
                });
            }
        }
    }
    for (const local of locals) {
        for (const other of otherLocalForwards) {
            if (localBindCollides(local, other.forward)) {
                errors.push({
                    field: 'forwards',
                    message: 'Local forward ' + local.bindHost + ':' + local.bindPort
                        + " conflicts with tunnel '" + other.tunnelName
                        + "', which already forwards that port on this host.",
                });
            }
        }
    }

    // Model declaration order (SshTunnel), trims exactly as collectInto:
    // password/passphrase raw off their fields, the PEM text raw off its area.
    const value = {
        id: selfId,
        name,
        enabled: bool(tunnel.enabled, true),
        host: str(tunnel.host),
        port,
        username: str(tunnel.username),
        authMethod,
        password,
        keySource,
        privateKeyPath: str(tunnel.privateKeyPath),
        privateKeyPem,
        privateKeyPassphrase: raw(tunnel.privateKeyPassphrase),
        verifyHostKey,
        acceptedHostKey,
        acceptedHostKeyType: raw(tunnel.acceptedHostKeyType),
        serverAliveIntervalSeconds,
        serverAliveCountMax,
        forwards,
    };

    return { errors, value };
}
