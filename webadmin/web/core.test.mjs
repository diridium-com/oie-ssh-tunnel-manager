// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * Golden tests for ssh-core.js against the exact strings the Swing client
 * renders (TunnelTableModel / TunnelStatusCellRenderer / TunnelDiagnosticsPane
 * / SshTunnelDialog and the shared Hosts / PortForward helpers), so the web
 * administrator stays byte-identical with the desktop client. Event-time
 * goldens are built from local-time Date components, so they hold in any time
 * zone; uptime/retry goldens pass an explicit nowMs, so they are deterministic.
 *
 * Run: npm test   (from webadmin/; node --test 'web/*.test.mjs')
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    fmtUptime, fmtNextRetry, humanizeDuration,
    forwardsSummary, endpointLabel, fmtEventTime,
    statusDisplay, hostKeyDisplay,
    isMasked, blankSecrets,
    mergeEvents, hostValidationError, validateTunnel,
} from './ssh-core.js';

const NOW = 1_760_000_000_000; // any fixed epoch; only deltas matter

/* ---- humanizeDuration (TunnelTableModel.humanizeDuration) ------------------- */

test('humanizeDuration: seconds-only below a minute', () => {
    assert.equal(humanizeDuration(0), '0s');
    assert.equal(humanizeDuration(999), '0s');
    assert.equal(humanizeDuration(5000), '5s');
    assert.equal(humanizeDuration(59999), '59s');
});

test('humanizeDuration: minutes carry seconds, hours carry minutes', () => {
    assert.equal(humanizeDuration(60000), '1m 0s');
    assert.equal(humanizeDuration(65000), '1m 5s');
    assert.equal(humanizeDuration(3599999), '59m 59s');
    assert.equal(humanizeDuration(3600000), '1h 0m');
    assert.equal(humanizeDuration(7325000), '2h 2m');
});

test('humanizeDuration: negative durations clamp to "0s"', () => {
    assert.equal(humanizeDuration(-1500), '0s');
});

/* ---- fmtUptime (TunnelTableModel.uptimeText) -------------------------------- */

test('fmtUptime: not connected (0/absent connectedSince) renders empty', () => {
    assert.equal(fmtUptime(0, NOW), '');
    assert.equal(fmtUptime(null, NOW), '');
    assert.equal(fmtUptime(undefined, NOW), '');
    assert.equal(fmtUptime('0', NOW), '');
});

test('fmtUptime: humanized age of the connection', () => {
    assert.equal(fmtUptime(NOW - 5000, NOW), '5s');
    assert.equal(fmtUptime(NOW - 65000, NOW), '1m 5s');
    assert.equal(fmtUptime(NOW - 3660000, NOW), '1h 1m');
});

test('fmtUptime: string-typed wire millis are coerced', () => {
    assert.equal(fmtUptime(String(NOW - 61000), String(NOW)), '1m 1s');
});

/* ---- fmtNextRetry (TunnelTableModel.nextRetryText) -------------------------- */

test('fmtNextRetry: no retry scheduled (0/absent) renders empty', () => {
    assert.equal(fmtNextRetry(0, NOW), '');
    assert.equal(fmtNextRetry(null, NOW), '');
    assert.equal(fmtNextRetry('0', NOW), '');
});

test('fmtNextRetry: past due renders "now" (boundary inclusive)', () => {
    assert.equal(fmtNextRetry(NOW - 1, NOW), 'now');
    assert.equal(fmtNextRetry(NOW, NOW), 'now');
    assert.equal(fmtNextRetry(NOW - 60000, NOW), 'now');
});

test('fmtNextRetry: future renders "in <duration>"', () => {
    // One millisecond out is still "in 0s", exactly like Swing (delta > 0).
    assert.equal(fmtNextRetry(NOW + 1, NOW), 'in 0s');
    assert.equal(fmtNextRetry(NOW + 5000, NOW), 'in 5s');
    assert.equal(fmtNextRetry(NOW + 90000, NOW), 'in 1m 30s');
    assert.equal(fmtNextRetry(NOW + 7200000, NOW), 'in 2h 0m');
});

/* ---- forwardsSummary (TunnelTableModel.forwardSummary) ---------------------- */

test('forwardsSummary: empty and absent lists render "0L / 0R"', () => {
    assert.equal(forwardsSummary([]), '0L / 0R');
    assert.equal(forwardsSummary(null), '0L / 0R');
    assert.equal(forwardsSummary(undefined), '0L / 0R');
    // XStream renders an empty collection as ''.
    assert.equal(forwardsSummary(''), '0L / 0R');
});

test('forwardsSummary: locals only, remotes only, and mixed', () => {
    assert.equal(forwardsSummary([{ direction: 'LOCAL' }, { direction: 'LOCAL' }]), '2L / 0R');
    assert.equal(forwardsSummary([{ direction: 'REMOTE' }, { direction: 'REMOTE' }]), '0L / 2R');
    assert.equal(forwardsSummary([
        { direction: 'LOCAL' }, { direction: 'REMOTE' }, { direction: 'LOCAL' },
    ]), '2L / 1R');
});

test('forwardsSummary: anything not REMOTE counts as local (Java else-branch)', () => {
    assert.equal(forwardsSummary([{}]), '1L / 0R');
});

test('forwardsSummary: XStream singleton collapse (bare object) tolerated', () => {
    assert.equal(forwardsSummary({ direction: 'REMOTE' }), '0L / 1R');
});

/* ---- endpointLabel (SshTunnel.getEndpointDescription) ----------------------- */

test('endpointLabel: "user@host:port"', () => {
    assert.equal(endpointLabel({ username: 'oie', host: 'gw.example.com', port: 22 }),
        'oie@gw.example.com:22');
    assert.equal(endpointLabel({ username: 'svc', host: '10.0.0.1', port: '2222' }),
        'svc@10.0.0.1:2222');
});

test('endpointLabel: missing fields read as empty, not "undefined"', () => {
    assert.equal(endpointLabel({}), '@:');
    assert.equal(endpointLabel(null), '@:');
});

/* ---- fmtEventTime (TunnelDiagnosticsPane TIME_FMT) -------------------------- */

test('fmtEventTime: HH:mm:ss local with zero padding', () => {
    // Built from local-time components, so the golden holds in any zone.
    assert.equal(fmtEventTime(new Date(2026, 0, 2, 4, 5, 6).getTime()), '04:05:06');
    assert.equal(fmtEventTime(new Date(2026, 5, 7, 0, 0, 0).getTime()), '00:00:00');
    assert.equal(fmtEventTime(new Date(2026, 11, 31, 23, 59, 59).getTime()), '23:59:59');
});

/* ---- statusDisplay (statusText + TunnelStatusCellRenderer) ------------------ */

test('statusDisplay: no runtime status falls back on the enabled flag', () => {
    assert.deepEqual(statusDisplay({ enabled: true }, null),
        { text: 'Disconnected', tone: 'plain' });
    assert.deepEqual(statusDisplay({ enabled: false }, null),
        { text: 'Disabled', tone: 'plain' });
    // Wire boolean quirk: the STRING 'false'.
    assert.deepEqual(statusDisplay({ enabled: 'false' }, null),
        { text: 'Disabled', tone: 'plain' });
});

test('statusDisplay: exact display texts for every state', () => {
    const texts = {
        CONNECTED: 'Connected',
        CONNECTING: 'Connecting',
        RECONNECTING: 'Reconnecting',
        DISCONNECTED: 'Disconnected',
        FAILED: 'Failed',
        DISABLED: 'Disabled',
    };
    for (const [state, text] of Object.entries(texts)) {
        assert.equal(statusDisplay({ enabled: true }, { state }).text, text, state);
    }
});

test('statusDisplay: FAILED is the ONLY red state — everything else is plain', () => {
    assert.equal(statusDisplay({ enabled: true }, { state: 'FAILED' }).tone, 'red');
    for (const state of ['CONNECTED', 'CONNECTING', 'RECONNECTING', 'DISCONNECTED', 'DISABLED']) {
        assert.equal(statusDisplay({ enabled: true }, { state }).tone, 'plain', state);
    }
    // The no-status fallbacks can never be red either.
    assert.equal(statusDisplay({ enabled: true }, null).tone, 'plain');
    assert.equal(statusDisplay({ enabled: false }, null).tone, 'plain');
});

test('statusDisplay: a status with no state reads as the model default Disconnected', () => {
    assert.deepEqual(statusDisplay({ enabled: true }, {}),
        { text: 'Disconnected', tone: 'plain' });
});

/* ---- hostKeyDisplay (Host Key column + renderer) ---------------------------- */

test('hostKeyDisplay: verification on is "Pinned" plain', () => {
    assert.deepEqual(hostKeyDisplay({ verifyHostKey: true }), { text: 'Pinned', tone: 'plain' });
    // Model default is verifyHostKey = true.
    assert.deepEqual(hostKeyDisplay({}), { text: 'Pinned', tone: 'plain' });
});

test('hostKeyDisplay: verification off is "Unverified" amber (standing warning)', () => {
    assert.deepEqual(hostKeyDisplay({ verifyHostKey: false }), { text: 'Unverified', tone: 'amber' });
    // Wire boolean quirk: the STRING 'false'.
    assert.deepEqual(hostKeyDisplay({ verifyHostKey: 'false' }), { text: 'Unverified', tone: 'amber' });
});

/* ---- isMasked / blankSecrets (SECRET_MASK semantics) ------------------------ */

test('isMasked: exactly the eight-asterisk mask, nothing else', () => {
    assert.equal(isMasked('********'), true);
    assert.equal(isMasked('******* '), false);
    assert.equal(isMasked('*********'), false);
    assert.equal(isMasked(''), false);
    assert.equal(isMasked(null), false);
    assert.equal(isMasked(undefined), false);
});

test('blankSecrets: blanks password, passphrase, AND private key; keeps the rest', () => {
    const source = {
        id: 't-1',
        name: 'Vendor VPN',
        host: 'gw.example.com',
        password: '********',
        privateKeyPath: '/etc/keys/id_ed25519',
        privateKeyPem: '********',
        privateKeyPassphrase: '********',
        acceptedHostKey: 'AAAA',
        forwards: [{ direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661 }],
    };
    const copy = blankSecrets(source);
    assert.equal(copy.password, '');
    assert.equal(copy.privateKeyPem, '');
    assert.equal(copy.privateKeyPassphrase, '');
    // Non-secret fields survive — the panel handles id-null and "(copy)" naming.
    assert.equal(copy.id, 't-1');
    assert.equal(copy.name, 'Vendor VPN');
    assert.equal(copy.privateKeyPath, '/etc/keys/id_ed25519');
    assert.equal(copy.acceptedHostKey, 'AAAA');
    assert.deepEqual(copy.forwards, source.forwards);
});

test('blankSecrets: returns a copy — mutating it leaves the source untouched', () => {
    const source = { password: 'p', forwards: [{ bindPort: 6661 }] };
    const copy = blankSecrets(source);
    copy.forwards[0].bindPort = 9999;
    copy.name = 'changed';
    assert.equal(source.forwards[0].bindPort, 6661);
    assert.equal(source.name, undefined);
    assert.equal(source.password, 'p');
});

/* ---- mergeEvents (TunnelDiagnosticsPane.refreshEvents) ---------------------- */

const EVENT_DATA = [
    {
        tunnelId: 'a',
        tunnelName: 'Vendor VPN',
        events: [
            { timestamp: 1000, level: 'INFO', message: 'Connecting' },
            { timestamp: 3000, level: 'ERROR', message: 'Auth failed' },
        ],
    },
    {
        tunnelId: 'b',
        tunnelName: 'Prod VPN',
        events: [
            { timestamp: 2000, level: 'WARN', message: 'Retrying' },
        ],
    },
];

test('mergeEvents: all tunnels (null filter), newest-first across tunnels', () => {
    const rows = mergeEvents(EVENT_DATA, null);
    assert.deepEqual(rows.map((r) => [r.timestamp, r.tunnelName, r.level, r.message]), [
        [3000, 'Vendor VPN', 'ERROR', 'Auth failed'],
        [2000, 'Prod VPN', 'WARN', 'Retrying'],
        [1000, 'Vendor VPN', 'INFO', 'Connecting'],
    ]);
});

test('mergeEvents: "This tunnel" filter keeps only the matching tunnel', () => {
    const rows = mergeEvents(EVENT_DATA, 'b');
    assert.deepEqual(rows.map((r) => [r.timestamp, r.tunnelId]), [[2000, 'b']]);
});

test('mergeEvents: filter ids compare String()-coerced', () => {
    const data = [{ tunnelId: 7, tunnelName: 'N', events: [{ timestamp: 1 }] }];
    assert.equal(mergeEvents(data, '7').length, 1);
    assert.equal(mergeEvents(data, 7).length, 1);
    assert.equal(mergeEvents(data, '8').length, 0);
});

test('mergeEvents: missing tunnelName falls back to the id (Swing getOrDefault)', () => {
    const rows = mergeEvents([{ tunnelId: 'x', events: [{ timestamp: 1 }] }], null);
    assert.equal(rows[0].tunnelName, 'x');
});

test('mergeEvents: level defaults to INFO, message to empty, timestamps coerced', () => {
    const rows = mergeEvents([{ tunnelId: 'a', tunnelName: 'A', events: [{ timestamp: '5' }] }], null);
    assert.deepEqual(rows, [{
        tunnelId: 'a', tunnelName: 'A', timestamp: 5, level: 'INFO', message: '',
    }]);
});

test('mergeEvents: equal timestamps keep encounter order (stable sort)', () => {
    const rows = mergeEvents([{
        tunnelId: 'a',
        tunnelName: 'A',
        events: [
            { timestamp: 100, message: 'first' },
            { timestamp: 100, message: 'second' },
        ],
    }], null);
    assert.deepEqual(rows.map((r) => r.message), ['first', 'second']);
});

test('mergeEvents: null input and XStream empty-collection events tolerated', () => {
    assert.deepEqual(mergeEvents(null, null), []);
    assert.deepEqual(mergeEvents([{ tunnelId: 'a', tunnelName: 'A', events: '' }], null), []);
});

/* ---- hostValidationError (shared Hosts helper) ------------------------------ */

test('hostValidationError: blank host is "<label> is required" (no trailing dot)', () => {
    assert.equal(hostValidationError('SSH host', '', false), 'SSH host is required');
    assert.equal(hostValidationError('SSH host', '   ', false), 'SSH host is required');
    assert.equal(hostValidationError('SSH host', null, false), 'SSH host is required');
});

test('hostValidationError: valid IPv4, hostname, FQDN, underscore, IPv6', () => {
    assert.equal(hostValidationError('X', '10.0.0.1', false), null);
    assert.equal(hostValidationError('X', '255.255.255.255', false), null);
    assert.equal(hostValidationError('X', 'gw.example.com', false), null);
    assert.equal(hostValidationError('X', 'gw.example.com.', false), null); // trailing dot = FQDN
    assert.equal(hostValidationError('X', 'host_1.example.com', false), null); // underscore allowed
    assert.equal(hostValidationError('X', '::1', false), null);
    assert.equal(hostValidationError('X', 'fe80::1%eth0', false), null); // zone id
    // Three numeric parts is not an IPv4 attempt; digit labels are legal hostnames.
    assert.equal(hostValidationError('X', '1.2.3', false), null);
});

test('hostValidationError: IPv4 attempt with a bad octet, verbatim message', () => {
    assert.equal(hostValidationError('SSH host', '999.1.1.1', false),
        "SSH host '999.1.1.1' is not a valid IP address (each octet must be 0-255)");
    assert.equal(hostValidationError('SSH host', '2000.1000.1.1', false),
        "SSH host '2000.1000.1.1' is not a valid IP address (each octet must be 0-255)");
});

test('hostValidationError: bad hostnames, verbatim message', () => {
    assert.equal(hostValidationError('SSH host', 'bad host', false),
        "SSH host 'bad host' is not a valid hostname or IP address");
    assert.equal(hostValidationError('X', '-bad.example.com', false),
        "X '-bad.example.com' is not a valid hostname or IP address");
    assert.equal(hostValidationError('X', 'a..b', false),
        "X 'a..b' is not a valid hostname or IP address");
    assert.equal(hostValidationError('X', 'a'.repeat(64) + '.com', false),
        "X '" + 'a'.repeat(64) + ".com' is not a valid hostname or IP address");
});

test('hostValidationError: bad IPv6, verbatim message', () => {
    assert.equal(hostValidationError('X', 'zzzz::1', false),
        "X 'zzzz::1' is not a valid IPv6 address");
    assert.equal(hostValidationError('X', 'example.com:22', false),
        "X 'example.com:22' is not a valid IPv6 address");
});

test('hostValidationError: wildcard only with allowWildcard (bind hosts)', () => {
    assert.equal(hostValidationError('Forward bind host', '*', true), null);
    assert.equal(hostValidationError('SSH host', '*', false),
        "SSH host '*' is not a valid hostname or IP address");
});

/* ---- validateTunnel (SshTunnelDialog.validateLocally) ----------------------- */

function validTunnel(overrides) {
    return Object.assign({
        id: 't-1',
        name: 'Vendor VPN',
        enabled: true,
        host: 'gw.example.com',
        port: 22,
        username: 'oie',
        authMethod: 'PASSWORD',
        password: 'hunter2',
        keySource: 'FILE',
        privateKeyPath: '',
        privateKeyPem: '',
        privateKeyPassphrase: '',
        verifyHostKey: true,
        acceptedHostKey: 'AAAAC3NzaC1lZDI1NTE5',
        acceptedHostKeyType: 'ssh-ed25519',
        serverAliveIntervalSeconds: 30,
        serverAliveCountMax: 3,
        forwards: [{
            direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661,
            destinationHost: 'vendor.internal', destinationPort: 6661,
        }],
    }, overrides);
}

test('validateTunnel: a fully valid tunnel passes and normalizes', () => {
    const { errors, value } = validateTunnel(validTunnel({
        id: 42,
        name: ' Vendor VPN ',
        enabled: 'false',
        host: ' gw.example.com ',
        port: '2222',
        username: ' oie ',
        password: ' secret ',
        verifyHostKey: 'true',
        serverAliveIntervalSeconds: '60',
        serverAliveCountMax: '5',
        forwards: [{
            direction: 'LOCAL', bindHost: ' 127.0.0.1 ', bindPort: '6661',
            destinationHost: ' vendor.internal ', destinationPort: '6661',
        }],
    }), []);
    assert.deepEqual(errors, []);
    assert.deepEqual(value, {
        id: '42',
        name: 'Vendor VPN',
        enabled: false,
        host: 'gw.example.com',
        port: 2222,
        username: 'oie',
        authMethod: 'PASSWORD',
        // Swing reads the password field raw — never trimmed.
        password: ' secret ',
        keySource: 'FILE',
        privateKeyPath: '',
        privateKeyPem: '',
        privateKeyPassphrase: '',
        verifyHostKey: true,
        acceptedHostKey: 'AAAAC3NzaC1lZDI1NTE5',
        acceptedHostKeyType: 'ssh-ed25519',
        serverAliveIntervalSeconds: 60,
        serverAliveCountMax: 5,
        forwards: [{
            direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661,
            destinationHost: 'vendor.internal', destinationPort: 6661,
        }],
    });
});

test('validateTunnel: an empty tunnel reports errors in dialog field order', () => {
    const { errors, value } = validateTunnel({}, []);
    assert.deepEqual(errors.map((e) => e.field),
        ['name', 'host', 'username', 'password', 'acceptedHostKey']);
    // Model defaults still land in value.
    assert.equal(value.port, 22);
    assert.equal(value.enabled, true);
    assert.equal(value.authMethod, 'PASSWORD');
    assert.equal(value.keySource, 'FILE');
    assert.equal(value.verifyHostKey, true);
    assert.equal(value.serverAliveIntervalSeconds, 30);
    assert.equal(value.serverAliveCountMax, 3);
    assert.deepEqual(value.forwards, []);
});

test('validateTunnel: name required, verbatim', () => {
    assert.deepEqual(validateTunnel(validTunnel({ name: '   ' }), []).errors,
        [{ field: 'name', message: 'Name is required.' }]);
});

test('validateTunnel: duplicate name is case-insensitive, verbatim single-quoted message', () => {
    const others = [{ id: 'x', name: 'vendor vpn' }];
    assert.deepEqual(validateTunnel(validTunnel({ id: null }), others).errors,
        [{ field: 'name', message: "A tunnel named 'Vendor VPN' already exists." }]);
    assert.equal(validateTunnel(validTunnel({ id: null, name: 'VENDOR VPN' }), others).errors.length, 1);
});

test('validateTunnel: editing a tunnel does not collide with its own name (id String-coerced)', () => {
    assert.deepEqual(validateTunnel(validTunnel({ id: 42 }),
        [{ id: '42', name: 'Vendor VPN' }]).errors, []);
    // A different tunnel with the same name still trips it.
    assert.equal(validateTunnel(validTunnel({ id: 42 }),
        [{ id: '43', name: 'Vendor VPN' }]).errors.length, 1);
});

test('validateTunnel: host syntax errors carry the trailing period the dialog appends', () => {
    assert.deepEqual(validateTunnel(validTunnel({ host: '' }), []).errors,
        [{ field: 'host', message: 'SSH host is required.' }]);
    assert.deepEqual(validateTunnel(validTunnel({ host: '999.1.1.1' }), []).errors,
        [{ field: 'host', message: "SSH host '999.1.1.1' is not a valid IP address (each octet must be 0-255)." }]);
    assert.deepEqual(validateTunnel(validTunnel({ host: 'bad host' }), []).errors,
        [{ field: 'host', message: "SSH host 'bad host' is not a valid hostname or IP address." }]);
    // The wildcard is never valid as an SSH host.
    assert.equal(validateTunnel(validTunnel({ host: '*' }), []).errors.length, 1);
});

test('validateTunnel: SSH port range 1-65535; blank applies the model default 22', () => {
    const message = 'SSH port must be between 1 and 65535.';
    assert.deepEqual(validateTunnel(validTunnel({ port: 0 }), []).errors,
        [{ field: 'port', message }]);
    assert.deepEqual(validateTunnel(validTunnel({ port: 65536 }), []).errors,
        [{ field: 'port', message }]);
    assert.deepEqual(validateTunnel(validTunnel({ port: 'abc' }), []).errors,
        [{ field: 'port', message }]);
    assert.deepEqual(validateTunnel(validTunnel({ port: '1.5' }), []).errors,
        [{ field: 'port', message }]);
    const blank = validateTunnel(validTunnel({ port: '' }), []);
    assert.deepEqual(blank.errors, []);
    assert.equal(blank.value.port, 22);
});

test('validateTunnel: username required, verbatim', () => {
    assert.deepEqual(validateTunnel(validTunnel({ username: '  ' }), []).errors,
        [{ field: 'username', message: 'Username is required.' }]);
});

test('validateTunnel: password auth requires a password — raw length, never trimmed', () => {
    assert.deepEqual(validateTunnel(validTunnel({ password: '' }), []).errors,
        [{ field: 'password', message: 'Password is required for password authentication.' }]);
    // A whitespace password has length > 0 and passes (Swing getPassword().length).
    assert.deepEqual(validateTunnel(validTunnel({ password: ' ' }), []).errors, []);
    // The mask counts as present: keep the stored password.
    assert.deepEqual(validateTunnel(validTunnel({ password: '********' }), []).errors, []);
});

test('validateTunnel: key auth with FILE source requires the server path', () => {
    const keyTunnel = (o) => validTunnel({
        authMethod: 'PRIVATE_KEY', password: '', keySource: 'FILE', ...o,
    });
    assert.deepEqual(validateTunnel(keyTunnel({ privateKeyPath: '  ' }), []).errors,
        [{ field: 'privateKeyPath', message: 'Private key path is required.' }]);
    assert.deepEqual(validateTunnel(keyTunnel({ privateKeyPath: '/etc/keys/id_ed25519' }), []).errors, []);
});

test('validateTunnel: key auth with INLINE source requires the PEM (mask = keep stored)', () => {
    const keyTunnel = (o) => validTunnel({
        authMethod: 'PRIVATE_KEY', password: '', keySource: 'INLINE', ...o,
    });
    assert.deepEqual(validateTunnel(keyTunnel({ privateKeyPem: ' \n ' }), []).errors,
        [{ field: 'privateKeyPem', message: 'Private key is required.' }]);
    assert.deepEqual(validateTunnel(keyTunnel({ privateKeyPem: '********' }), []).errors, []);
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n';
    const ok = validateTunnel(keyTunnel({ privateKeyPem: pem }), []);
    assert.deepEqual(ok.errors, []);
    // The PEM text is stored raw, exactly as typed (Swing does not trim it).
    assert.equal(ok.value.privateKeyPem, pem);
});

test('validateTunnel: host key must be accepted when verification is on, verbatim', () => {
    assert.deepEqual(validateTunnel(validTunnel({ acceptedHostKey: '' }), []).errors, [{
        field: 'acceptedHostKey',
        message: 'Host key verification is enabled but no host key has been accepted.'
            + ' Fetch and accept the host key, or turn off verification.',
    }]);
    // Verification off: no accepted key needed.
    assert.deepEqual(validateTunnel(validTunnel({
        verifyHostKey: false, acceptedHostKey: '',
    }), []).errors, []);
});

test('validateTunnel: keep-alive spinner ranges 0-3600 and 1-20; blanks default 30/3', () => {
    assert.deepEqual(validateTunnel(validTunnel({ serverAliveIntervalSeconds: 3601 }), []).errors,
        [{ field: 'serverAliveIntervalSeconds', message: 'Keep-alive (sec) must be between 0 and 3600.' }]);
    assert.deepEqual(validateTunnel(validTunnel({ serverAliveCountMax: 0 }), []).errors,
        [{ field: 'serverAliveCountMax', message: 'Keep-alive retries must be between 1 and 20.' }]);
    assert.deepEqual(validateTunnel(validTunnel({ serverAliveCountMax: 21 }), []).errors,
        [{ field: 'serverAliveCountMax', message: 'Keep-alive retries must be between 1 and 20.' }]);
    const ok = validateTunnel(validTunnel({
        serverAliveIntervalSeconds: '', serverAliveCountMax: '',
    }), []);
    assert.deepEqual(ok.errors, []);
    assert.equal(ok.value.serverAliveIntervalSeconds, 30);
    assert.equal(ok.value.serverAliveCountMax, 3);
    // 0 is a legal keep-alive interval (disables keep-alive).
    const zero = validateTunnel(validTunnel({ serverAliveIntervalSeconds: 0 }), []);
    assert.deepEqual(zero.errors, []);
    assert.equal(zero.value.serverAliveIntervalSeconds, 0);
});

test('validateTunnel: forward direction must be Local or Remote', () => {
    const { errors } = validateTunnel(validTunnel({
        forwards: [{ direction: 'SIDEWAYS', bindHost: '127.0.0.1', bindPort: 1, destinationHost: 'd', destinationPort: 1 }],
    }), []);
    assert.deepEqual(errors,
        [{ field: 'forwards[0].direction', message: 'Every forward needs a direction (Local or Remote).' }]);
});

test('validateTunnel: forward bind host allows the wildcard; destination never does', () => {
    const wildcardBind = validateTunnel(validTunnel({
        forwards: [{ direction: 'LOCAL', bindHost: '*', bindPort: 6661, destinationHost: 'db', destinationPort: 5432 }],
    }), []);
    assert.deepEqual(wildcardBind.errors, []);
    const wildcardDest = validateTunnel(validTunnel({
        forwards: [{ direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: '*', destinationPort: 5432 }],
    }), []);
    assert.deepEqual(wildcardDest.errors, [{
        field: 'forwards[0].destinationHost',
        message: "Forward destination host '*' is not a valid hostname or IP address.",
    }]);
});

test('validateTunnel: forward host syntax errors, verbatim with trailing period', () => {
    const { errors } = validateTunnel(validTunnel({
        forwards: [{ direction: 'LOCAL', bindHost: 'bad host', bindPort: 1, destinationHost: '', destinationPort: 1 }],
    }), []);
    assert.deepEqual(errors, [
        { field: 'forwards[0].bindHost', message: "Forward bind host 'bad host' is not a valid hostname or IP address." },
        { field: 'forwards[0].destinationHost', message: 'Forward destination host is required.' },
    ]);
});

test('validateTunnel: forward ports must be numeric and 1-65535 (unparseable reads as 0)', () => {
    const bindMsg = 'Every forward needs a bind port between 1 and 65535.';
    const destMsg = 'Every forward needs a destination port between 1 and 65535.';
    const fwd = (o) => validTunnel({
        forwards: [{ direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'd', destinationPort: 5432, ...o }],
    });
    assert.deepEqual(validateTunnel(fwd({ bindPort: 0 }), []).errors,
        [{ field: 'forwards[0].bindPort', message: bindMsg }]);
    assert.deepEqual(validateTunnel(fwd({ bindPort: 'abc' }), []).errors,
        [{ field: 'forwards[0].bindPort', message: bindMsg }]);
    assert.deepEqual(validateTunnel(fwd({ bindPort: 65536 }), []).errors,
        [{ field: 'forwards[0].bindPort', message: bindMsg }]);
    assert.deepEqual(validateTunnel(fwd({ destinationPort: 70000 }), []).errors,
        [{ field: 'forwards[0].destinationPort', message: destMsg }]);
    assert.deepEqual(validateTunnel(fwd({ destinationPort: '' }), []).errors,
        [{ field: 'forwards[0].destinationPort', message: destMsg }]);
});

test('validateTunnel: in-tunnel local bind collision, wildcard- and alias-aware', () => {
    const two = (a, b) => validTunnel({
        forwards: [
            { direction: 'LOCAL', bindHost: a, bindPort: 6661, destinationHost: 'd', destinationPort: 1 },
            { direction: 'LOCAL', bindHost: b, bindPort: 6661, destinationHost: 'd', destinationPort: 2 },
        ],
    });
    // localhost is an alias for 127.0.0.1; the message names the FIRST of the pair.
    assert.deepEqual(validateTunnel(two('127.0.0.1', 'localhost'), []).errors,
        [{ field: 'forwards', message: 'Two local forwards bind the same address (127.0.0.1:6661).' }]);
    // A wildcard bind overlaps any host.
    assert.deepEqual(validateTunnel(two('0.0.0.0', '10.1.1.1'), []).errors,
        [{ field: 'forwards', message: 'Two local forwards bind the same address (0.0.0.0:6661).' }]);
    assert.equal(validateTunnel(two('::', '10.1.1.1'), []).errors.length, 1);
    // Different hosts on the same port coexist.
    assert.deepEqual(validateTunnel(two('10.1.1.1', '10.1.1.2'), []).errors, []);
});

test('validateTunnel: same bind on different ports or directions is no collision', () => {
    const ok = validateTunnel(validTunnel({
        forwards: [
            { direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'd', destinationPort: 1 },
            { direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6662, destinationHost: 'd', destinationPort: 2 },
            { direction: 'REMOTE', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'd', destinationPort: 3 },
        ],
    }), []);
    assert.deepEqual(ok.errors, []);
});

test('validateTunnel: cross-tunnel collision names the conflicting tunnel, verbatim', () => {
    const others = [{
        id: 'x',
        name: 'Prod VPN',
        forwards: [{ direction: 'LOCAL', bindHost: '0.0.0.0', bindPort: 6661, destinationHost: 'p', destinationPort: 1 }],
    }];
    const { errors } = validateTunnel(validTunnel({ id: null, name: 'New Tunnel' }), others);
    assert.deepEqual(errors, [{
        field: 'forwards',
        message: "Local forward 127.0.0.1:6661 conflicts with tunnel 'Prod VPN',"
            + ' which already forwards that port on this host.',
    }]);
});

test('validateTunnel: cross-tunnel check excludes the tunnel under edit', () => {
    const others = [{
        id: 't-1',
        name: 'Vendor VPN',
        forwards: [{ direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'v', destinationPort: 1 }],
    }];
    // Same id as validTunnel(): its own stored copy is not a conflict.
    assert.deepEqual(validateTunnel(validTunnel(), others).errors, []);
});

test('validateTunnel: only other tunnels\' LOCAL forwards can conflict', () => {
    const remoteOther = [{
        id: 'x', name: 'Prod VPN',
        forwards: [{ direction: 'REMOTE', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'p', destinationPort: 1 }],
    }];
    assert.deepEqual(validateTunnel(validTunnel({ id: null }), remoteOther).errors, []);
    const differentPort = [{
        id: 'x', name: 'Prod VPN',
        forwards: [{ direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6662, destinationHost: 'p', destinationPort: 1 }],
    }];
    assert.deepEqual(validateTunnel(validTunnel({ id: null }), differentPort).errors, []);
});

test('validateTunnel: cross-tunnel check tolerates XStream singleton forwards', () => {
    const others = [{
        id: 'x',
        name: 'Prod VPN',
        // Singleton collapse: one forward arrives as a bare object, not a list.
        forwards: { direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'p', destinationPort: 1 },
    }];
    const { errors } = validateTunnel(validTunnel({ id: null, name: 'New Tunnel' }), others);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /conflicts with tunnel 'Prod VPN'/);
});

test('validateTunnel: wildcard bind in the edited tunnel collides cross-tunnel too', () => {
    const others = [{
        id: 'x', name: 'Prod VPN',
        forwards: [{ direction: 'LOCAL', bindHost: '10.0.0.5', bindPort: 6661, destinationHost: 'p', destinationPort: 1 }],
    }];
    const { errors } = validateTunnel(validTunnel({
        id: null,
        name: 'New Tunnel',
        forwards: [{ direction: 'LOCAL', bindHost: '*', bindPort: 6661, destinationHost: 'd', destinationPort: 1 }],
    }), others);
    assert.deepEqual(errors, [{
        field: 'forwards',
        message: "Local forward *:6661 conflicts with tunnel 'Prod VPN',"
            + ' which already forwards that port on this host.',
    }]);
});

test('validateTunnel: errors accumulate in field order (errors[0] = what Swing shows)', () => {
    const { errors } = validateTunnel(validTunnel({
        name: '', host: 'bad host', username: '', password: '',
    }), []);
    assert.deepEqual(errors.map((e) => e.field), ['name', 'host', 'username', 'password']);
    assert.equal(errors[0].message, 'Name is required.');
});
