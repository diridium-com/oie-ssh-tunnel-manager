// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * REST bindings for the SSH tunnel servlet at /extensions/oie-ssh-tunnel-manager
 * (SshTunnelServletInterface), plus normalization of the engine's XStream JSON
 * wire shapes.
 *
 * Reads go through the host's JSON pipeline (unwrap/asList). NONE of the
 * plugin's model classes carry an @XStreamAlias (the "tunnel"/"forward"
 * aliases in SshTunnelService are its private at-rest persistence form, never
 * the REST wire), so every root key is the fully-qualified class name, e.g.
 * {"list":{"com.diridium.oie.sshtunnel.SshTunnel":[...]}}. The host's asList
 * already tolerates that by matching the class name's last segment, so the
 * short keys ('sshTunnel', 'sshTunnelStatus', 'tunnelEvent') passed below
 * cover both the FQCN root and any future alias. Nested List fields
 * (SshTunnel.forwards, DiagnosticResult.steps) arrive keyed the same way and
 * are unwrapped here. XStream quirks handled: one-element collections collapse
 * to a bare object, empty collections arrive as '', numbers can arrive as
 * strings, booleans can arrive as the STRING 'false', and enums arrive as
 * their name() ('PASSWORD', 'LOCAL', 'FAIL', ...).
 *
 * Writes are hand-built XStream XML (<com.diridium.oie.sshtunnel.SshTunnel>...)
 * sent via api.postXml/putXml — byte-parity with what the Swing client's
 * ObjectXMLSerializer produces (rbac/cache precedent), sidestepping the
 * unverified Jettison JSON request shapes.
 *
 * SECRETS: the server masks password/privateKeyPem/privateKeyPassphrase as
 * SECRET_MASK before they leave the engine; sending the mask back means "keep
 * the stored value" (resolved against the tunnel with the same ID, which is
 * why testConnection/derivePublicKey serialize WITH the id). Secrets are never
 * trimmed anywhere in this module.
 *
 * Errors are NOT toasted here — callers (panel/dialogs) surface failures via
 * platform.ui.toast, mapping 403 to the plugin's viewSshTunnels /
 * manageSshTunnels permissions and 404/501 to plugin-not-installed.
 */

const EXT = '/extensions/oie-ssh-tunnel-manager';

const TUNNEL_FQCN = 'com.diridium.oie.sshtunnel.SshTunnel';
const FORWARD_FQCN = 'com.diridium.oie.sshtunnel.PortForward';
const STEP_FQCN = 'com.diridium.oie.sshtunnel.DiagnosticStep';

/** Placeholder the server returns instead of a stored secret (SshTunnel.SECRET_MASK). */
export const SECRET_MASK = '********';

const enc = encodeURIComponent;

/* ---- wire-shape normalization (pure; unit-testable) ------------------------ */

// Missing/empty -> [], singleton -> [x] (XStream one-element collections arrive
// as a bare object).
function toArray(v) {
    if (v === null || v === undefined || v === '') return [];
    return Array.isArray(v) ? v : [v];
}

function str(v, dflt = '') {
    return v === undefined || v === null ? dflt : String(v);
}

// Numbers can arrive as JSON numbers or as strings ("2222"); Number() maps
// both, and ''/missing take the model's default.
function num(v, dflt = 0) {
    return v === undefined || v === null || v === '' ? dflt : Number(v);
}

// Booleans can arrive as the STRING 'false'; missing falls back to the model's
// default.
function bool(v, dflt) {
    return v === undefined || v === null ? dflt : String(v) !== 'false';
}

// Server-generated UUID string, or null when absent.
function idOrNull(v) {
    return v === undefined || v === null || v === '' ? null : String(v);
}

/* A nested List<T> field arrives keyed by the item class's root name (the
   FQCN here, since no model carries an @XStreamAlias): {"<fqcn>":[...]} for
   plural, a bare {"<fqcn>":{...}} singleton, or '' when empty. Mirrors the
   host asList's lone-key fallback for alias drift. */
function nestedList(v, key) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
        if (v[key] !== undefined) {
            v = v[key];
        } else {
            const keys = Object.keys(v).filter(k => !k.startsWith('@'));
            if (keys.length === 1) v = v[keys[0]];
        }
    }
    return toArray(v);
}

/* Coerce a raw wire PortForward into the stable client shape. */
function normalizeForward(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        direction: str(raw.direction, 'LOCAL'),
        bindHost: str(raw.bindHost, '127.0.0.1'),
        bindPort: num(raw.bindPort),
        destinationHost: str(raw.destinationHost),
        destinationPort: num(raw.destinationPort)
    };
}

/* Coerce a raw wire SshTunnel into the stable client shape. Secret fields
   (password, privateKeyPem, privateKeyPassphrase) usually hold SECRET_MASK —
   they pass through untouched, never trimmed. */
export function normalizeTunnel(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        id: idOrNull(raw.id),
        name: str(raw.name),
        enabled: bool(raw.enabled, true),
        host: str(raw.host),
        port: num(raw.port, 22),
        username: str(raw.username),
        authMethod: str(raw.authMethod, 'PASSWORD'),
        password: str(raw.password),
        keySource: str(raw.keySource, 'FILE'),
        privateKeyPath: str(raw.privateKeyPath),
        privateKeyPem: str(raw.privateKeyPem),
        privateKeyPassphrase: str(raw.privateKeyPassphrase),
        verifyHostKey: bool(raw.verifyHostKey, true),
        acceptedHostKey: str(raw.acceptedHostKey),
        acceptedHostKeyType: str(raw.acceptedHostKeyType),
        serverAliveIntervalSeconds: num(raw.serverAliveIntervalSeconds, 30),
        serverAliveCountMax: num(raw.serverAliveCountMax, 3),
        forwards: nestedList(raw.forwards, FORWARD_FQCN).map(normalizeForward).filter(Boolean)
    };
}

/* Coerce a raw wire SshTunnelStatus into the stable client shape. The epoch
   fields (connectedSince, nextRetryAt) are longs that can arrive as strings;
   0 means "not connected" / "no retry scheduled". */
export function normalizeStatus(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        tunnelId: idOrNull(raw.tunnelId),
        state: str(raw.state, 'DISCONNECTED'),
        lastError: str(raw.lastError),
        connectedSince: num(raw.connectedSince),
        failedAttempts: num(raw.failedAttempts),
        nextRetryAt: num(raw.nextRetryAt)
    };
}

/* Coerce a raw wire TunnelEvent into the stable client shape. level is the
   TunnelEvent.Level name: INFO | WARN | ERROR. */
export function normalizeEvent(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        timestamp: num(raw.timestamp),
        level: str(raw.level, 'INFO'),
        message: str(raw.message)
    };
}

/* Coerce one DiagnosticStep: status is the StepStatus name (PASS | WARN |
   FAIL | SKIP); hint is optional actionable guidance ('' when absent). */
function normalizeStep(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        name: str(raw.name),
        status: str(raw.status, 'SKIP'),
        detail: str(raw.detail),
        durationMs: num(raw.durationMs),
        hint: str(raw.hint)
    };
}

/* Coerce a raw wire DiagnosticResult into the stable client shape. The steps
   List<DiagnosticStep> arrives keyed by the step FQCN (plural, singleton
   collapse, or '' — the server always sends at least one step in practice). */
export function normalizeDiagnosticResult(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        success: bool(raw.success, false),
        summary: str(raw.summary),
        steps: nestedList(raw.steps, STEP_FQCN).map(normalizeStep).filter(Boolean)
    };
}

/* Coerce a raw wire HostKeyInfo into the stable client shape: publicKey is the
   base64 wire-format blob stored on acceptance, fingerprint the SHA256:...
   display form. */
export function normalizeHostKeyInfo(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        keyType: str(raw.keyType),
        fingerprint: str(raw.fingerprint),
        publicKey: str(raw.publicKey)
    };
}

/* ---- XStream XML writes ----------------------------------------------------- */

function escapeXml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/* One PortForward item, in the model's declared field order. Enum values are
   XStream name() strings (LOCAL | REMOTE). */
function forwardXml(f) {
    const parts = [];
    parts.push(`<direction>${escapeXml(f.direction ?? 'LOCAL')}</direction>`);
    parts.push(`<bindHost>${escapeXml(f.bindHost ?? '127.0.0.1')}</bindHost>`);
    parts.push(`<bindPort>${Number(f.bindPort ?? 0)}</bindPort>`);
    parts.push(`<destinationHost>${escapeXml(f.destinationHost ?? '')}</destinationHost>`);
    parts.push(`<destinationPort>${Number(f.destinationPort ?? 0)}</destinationPort>`);
    return `<${FORWARD_FQCN}>${parts.join('')}</${FORWARD_FQCN}>`;
}

/* Serialize a tunnel the way XStream expects — FQCN root element (no
   @XStreamAlias on the model), fields in SshTunnel's declared order, nested
   forwards as FQCN-named items. The <id> element is omitted unless includeId
   (Swing parity: create sends a null id, which XStream omits; update and the
   masked-secret-resolving helpers send it). Secret fields ride through
   escaped but otherwise untouched — the mask string means keep-stored-value,
   and real values are never trimmed. */
export function tunnelXml(t, { includeId = false } = {}) {
    const parts = [];
    if (includeId && t.id !== null && t.id !== undefined && t.id !== '') {
        parts.push(`<id>${escapeXml(t.id)}</id>`);
    }
    parts.push(`<name>${escapeXml(t.name ?? '')}</name>`);
    // Tolerate the boolean-as-string wire quirk on round-tripped tunnels;
    // missing falls back to the model's default.
    parts.push(`<enabled>${String(t.enabled ?? true) !== 'false'}</enabled>`);
    parts.push(`<host>${escapeXml(t.host ?? '')}</host>`);
    parts.push(`<port>${Number(t.port ?? 22)}</port>`);
    parts.push(`<username>${escapeXml(t.username ?? '')}</username>`);
    parts.push(`<authMethod>${escapeXml(t.authMethod ?? 'PASSWORD')}</authMethod>`);
    parts.push(`<password>${escapeXml(t.password ?? '')}</password>`);
    parts.push(`<keySource>${escapeXml(t.keySource ?? 'FILE')}</keySource>`);
    parts.push(`<privateKeyPath>${escapeXml(t.privateKeyPath ?? '')}</privateKeyPath>`);
    parts.push(`<privateKeyPem>${escapeXml(t.privateKeyPem ?? '')}</privateKeyPem>`);
    parts.push(`<privateKeyPassphrase>${escapeXml(t.privateKeyPassphrase ?? '')}</privateKeyPassphrase>`);
    parts.push(`<verifyHostKey>${String(t.verifyHostKey ?? true) !== 'false'}</verifyHostKey>`);
    parts.push(`<acceptedHostKey>${escapeXml(t.acceptedHostKey ?? '')}</acceptedHostKey>`);
    parts.push(`<acceptedHostKeyType>${escapeXml(t.acceptedHostKeyType ?? '')}</acceptedHostKeyType>`);
    parts.push(`<serverAliveIntervalSeconds>${Number(t.serverAliveIntervalSeconds ?? 30)}</serverAliveIntervalSeconds>`);
    parts.push(`<serverAliveCountMax>${Number(t.serverAliveCountMax ?? 3)}</serverAliveCountMax>`);
    parts.push(`<forwards>${(t.forwards ?? []).map(forwardXml).join('')}</forwards>`);
    return `<${TUNNEL_FQCN}>${parts.join('')}</${TUNNEL_FQCN}>`;
}

/* ---- REST client (the SshTunnelServletInterface endpoints) ------------------- */

export function makeApi(api) {
    return {
        // Tunnel CRUD
        getTunnels: async () =>
            api.asList(await api.get(`${EXT}/tunnels`), 'sshTunnel').map(normalizeTunnel).filter(Boolean),
        createTunnel: async (t) =>
            normalizeTunnel(await api.postXml(`${EXT}/tunnels`, tunnelXml(t))),
        updateTunnel: async (id, t) =>
            normalizeTunnel(await api.putXml(`${EXT}/tunnels/${enc(id)}`, tunnelXml(t, { includeId: true }))),
        deleteTunnel: (id) => api.del(`${EXT}/tunnels/${enc(id)}`),
        // Runtime control & status
        getStatuses: async () =>
            api.asList(await api.get(`${EXT}/statuses`), 'sshTunnelStatus').map(normalizeStatus).filter(Boolean),
        getTunnelEvents: async (id) =>
            api.asList(await api.get(`${EXT}/tunnels/${enc(id)}/events`), 'tunnelEvent').map(normalizeEvent).filter(Boolean),
        startTunnel: (id) => api.post(`${EXT}/tunnels/${enc(id)}/_start`, null),
        stopTunnel: (id) => api.post(`${EXT}/tunnels/${enc(id)}/_stop`, null),
        // Connection helpers — testConnection/derivePublicKey serialize WITH the
        // id so the server can resolve masked secrets against the stored tunnel.
        testConnection: async (t) =>
            normalizeDiagnosticResult(await api.postXml(`${EXT}/_testConnection`, tunnelXml(t, { includeId: true }))),
        fetchHostKey: async (host, port) =>
            normalizeHostKeyInfo(await api.post(`${EXT}/_fetchHostKey`, null, { params: { host, port } })),
        // derivePublicKey/revealPrivateKey answer a plain String, which the host
        // pipeline unwraps from {"string":"..."} (or passes through as text).
        derivePublicKey: async (t) =>
            str(await api.postXml(`${EXT}/_derivePublicKey`, tunnelXml(t, { includeId: true }))),
        revealPrivateKey: async (id) =>
            str(await api.post(`${EXT}/tunnels/${enc(id)}/_revealKey`, null))
    };
}
