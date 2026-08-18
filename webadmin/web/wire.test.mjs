// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * Wire-parsing tests for ssh-api.js against the engine's XStream JSON shapes.
 * No plugin model class carries an @XStreamAlias, so every root key is the
 * fully-qualified class name ({"list":{"com.diridium.oie.sshtunnel.SshTunnel":
 * [...]}}), and nested List fields (forwards, steps) are keyed the same way.
 * Covered quirks: singleton collapse (one-element collections arrive as a bare
 * object), '' for an empty collection, numbers-as-strings (epochs, ports),
 * booleans as the STRING 'false', masked secrets riding through untouched, and
 * 204/empty bodies -> null. Plus golden-string asserts on the XStream XML
 * write path (FQCN roots, declared field order, nested forwards, escaping).
 *
 * The normalizers receive values AFTER the web host's JSON pipeline has
 * stripped the single root key, so the unwrap/asList below are vendored
 * VERBATIM from the host (oie-web-client web-administrator/client/core/
 * api.js) to exercise the exact pipeline the plugin runs behind.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    makeApi, normalizeTunnel, normalizeStatus, normalizeEvent,
    normalizeDiagnosticResult, normalizeHostKeyInfo, tunnelXml, SECRET_MASK
} from './ssh-api.js';

/* ---- host JSON pipeline, vendored verbatim from client/core/api.js ---------- */

function unwrap(parsed) {
    // XStream JSON puts the payload under a single root key.
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const keys = Object.keys(parsed);
        if (keys.length === 1)
            return parsed[keys[0]];
    }
    return parsed;
}

/* When the engine returns a singleton or missing list, normalize to an array.
   XStream JSON renders one-element collections as a bare object, and classes
   without an @XStreamAlias use their fully-qualified name as the wrapper key
   (e.g. {"list":{"com.mirth...ServerLogItem":[...]}}). */
function asList(value, key) {
    if (value === null || value === undefined || value === '')
        return [];
    if (key !== undefined && value && typeof value === 'object' && !Array.isArray(value)) {
        if (value[key] !== undefined) {
            value = value[key];
        }
        else {
            const keys = Object.keys(value).filter(k => !k.startsWith('@'));
            if (keys.length === 1) {
                const lastSegment = (keys[0].split('.').pop() ?? '').toLowerCase();
                // Unwrap when the lone key is the FQCN form of the expected
                // alias, or when it plainly holds the array we asked for.
                if (lastSegment === key.toLowerCase() || Array.isArray(value[keys[0]])) {
                    value = value[keys[0]];
                }
            }
        }
        if (value === null || value === undefined || value === '')
            return [];
    }
    return Array.isArray(value) ? value : [value];
}

// A fake platform.api: reads answer unwrap(JSON.parse(fixture)) exactly like
// the host's parseBody does for JSON bodies (null = empty body / 204), and
// every call is recorded so tests can assert paths, params, and XML bodies.
function fakeApiFor(routes) {
    const calls = [];
    const parse = (body) => body == null ? null : unwrap(JSON.parse(body));
    const route = (method, path) => {
        assert.ok(Object.hasOwn(routes, path), `unexpected ${method} ${path}`);
        return parse(routes[path]);
    };
    return {
        calls,
        asList,
        get: async (path, params) => {
            calls.push({ method: 'GET', path, params });
            return route('GET', path);
        },
        post: async (path, body, opts) => {
            calls.push({ method: 'POST', path, body, params: opts?.params });
            return Object.hasOwn(routes, path) ? parse(routes[path]) : null;
        },
        postXml: async (path, xml, params) => {
            calls.push({ method: 'POST-XML', path, xml, params });
            return route('POST', path);
        },
        putXml: async (path, xml, params) => {
            calls.push({ method: 'PUT-XML', path, xml, params });
            return route('PUT', path);
        },
        del: async (path) => {
            calls.push({ method: 'DELETE', path });
            return null;
        }
    };
}

const EXT = '/extensions/oie-ssh-tunnel-manager';

const T_FQCN = 'com.diridium.oie.sshtunnel.SshTunnel';
const F_FQCN = 'com.diridium.oie.sshtunnel.PortForward';
const R_FQCN = 'com.diridium.oie.sshtunnel.DiagnosticResult';
const D_FQCN = 'com.diridium.oie.sshtunnel.DiagnosticStep';

/* ---- fixtures: FQCN-keyed roots (no @XStreamAlias on any model) -------------- */

// Two tunnels: the first with native JSON types and a plural forwards list;
// the second exercising numbers-as-strings, boolean-as-STRING-'false', masked
// secrets, and the forwards singleton collapse.
const WIRE_TUNNELS = `{"list":{"${T_FQCN}":[`
    + '{"id":"t-1","name":"Vendor VPN","enabled":true,"host":"ssh.vendor.example","port":22,'
    + '"username":"oie","authMethod":"PASSWORD","password":"********",'
    + '"keySource":"FILE","privateKeyPath":"","privateKeyPem":"","privateKeyPassphrase":"",'
    + '"verifyHostKey":true,"acceptedHostKey":"AAAAC3NzaC1lZDI1NTE5","acceptedHostKeyType":"ssh-ed25519",'
    + '"serverAliveIntervalSeconds":30,"serverAliveCountMax":3,'
    + `"forwards":{"${F_FQCN}":[`
    + '{"direction":"LOCAL","bindHost":"127.0.0.1","bindPort":6661,"destinationHost":"vendor-hl7","destinationPort":6661},'
    + '{"direction":"REMOTE","bindHost":"0.0.0.0","bindPort":9090,"destinationHost":"127.0.0.1","destinationPort":8443}'
    + ']}},'
    + '{"id":"t-2","name":"Lab uplink","enabled":"false","host":"lab.example","port":"2222",'
    + '"username":"svc","authMethod":"PRIVATE_KEY","password":"",'
    + '"keySource":"INLINE","privateKeyPath":"","privateKeyPem":"********","privateKeyPassphrase":"********",'
    + '"verifyHostKey":"false","acceptedHostKey":"","acceptedHostKeyType":"",'
    + '"serverAliveIntervalSeconds":"15","serverAliveCountMax":"5",'
    + `"forwards":{"${F_FQCN}":`
    + '{"direction":"LOCAL","bindHost":"127.0.0.1","bindPort":"5432","destinationHost":"db.internal","destinationPort":"5432"}}}'
    + ']}}';

// One tunnel whose list AND forwards both hit the empty/singleton edges: the
// list collapsed to a bare object, forwards empty ('').
const WIRE_TUNNELS_SINGLETON = `{"list":{"${T_FQCN}":`
    + '{"id":"t-3","name":"Bare","enabled":true,"host":"h","port":22,"username":"u",'
    + '"authMethod":"PASSWORD","password":"********","keySource":"FILE",'
    + '"privateKeyPath":"","privateKeyPem":"","privateKeyPassphrase":"",'
    + '"verifyHostKey":true,"acceptedHostKey":"","acceptedHostKeyType":"",'
    + '"serverAliveIntervalSeconds":30,"serverAliveCountMax":3,"forwards":""}}}';

// A single tunnel echo (create/update responses): bare FQCN root.
const WIRE_TUNNEL_ECHO = `{"${T_FQCN}":`
    + '{"id":"t-9","name":"Vendor VPN","enabled":true,"host":"ssh.vendor.example","port":22,'
    + '"username":"oie","authMethod":"PASSWORD","password":"********","keySource":"FILE",'
    + '"privateKeyPath":"","privateKeyPem":"","privateKeyPassphrase":"",'
    + '"verifyHostKey":true,"acceptedHostKey":"","acceptedHostKeyType":"",'
    + '"serverAliveIntervalSeconds":30,"serverAliveCountMax":3,'
    + `"forwards":{"${F_FQCN}":`
    + '{"direction":"LOCAL","bindHost":"127.0.0.1","bindPort":6661,"destinationHost":"vendor-hl7","destinationPort":6661}}}}';

// Statuses: epoch longs arrive as strings on the second entry.
const WIRE_STATUSES = '{"list":{"com.diridium.oie.sshtunnel.SshTunnelStatus":['
    + '{"tunnelId":"t-1","state":"CONNECTED","lastError":"","connectedSince":1755500000000,'
    + '"failedAttempts":0,"nextRetryAt":0},'
    + '{"tunnelId":"t-2","state":"RECONNECTING","lastError":"Auth fail","connectedSince":"0",'
    + '"failedAttempts":"4","nextRetryAt":"1755500123456"}'
    + ']}}';

const WIRE_EVENTS = '{"list":{"com.diridium.oie.sshtunnel.TunnelEvent":['
    + '{"timestamp":"1755500000000","level":"INFO","message":"Connected"},'
    + '{"timestamp":1755500060000,"level":"ERROR","message":"Connection lost: broken pipe"}'
    + ']}}';

// A diagnostic whose steps List collapsed to one bare step with NO hint field.
const WIRE_DIAG_SINGLETON = `{"${R_FQCN}":{`
    + '"success":"false","summary":"Failed at: TCP connect - timeout",'
    + `"steps":{"${D_FQCN}":`
    + '{"name":"TCP connect","status":"FAIL","detail":"timeout","durationMs":"5003"}}}}';

// A multi-step diagnostic: WARN step carries a hint, durations mix types.
const WIRE_DIAG = `{"${R_FQCN}":{`
    + '"success":true,"summary":"All checks passed (1 warning(s)).",'
    + `"steps":{"${D_FQCN}":[`
    + '{"name":"DNS resolve","status":"PASS","detail":"93.184.216.34","durationMs":12},'
    + '{"name":"Host key","status":"WARN","detail":"unverified","durationMs":"88",'
    + '"hint":"Fetch and accept the host key."},'
    + '{"name":"Port forwards","status":"SKIP","detail":"","durationMs":0}'
    + ']}}}';

const WIRE_HOST_KEY = '{"com.diridium.oie.sshtunnel.HostKeyInfo":{'
    + '"keyType":"ssh-ed25519","fingerprint":"SHA256:Qz5cAbCd","publicKey":"AAAAC3NzaC1lZDI1NTE5"}}';

/* ---- tunnels list: plural, singleton collapse, empty -------------------------- */

test('getTunnels parses a two-tunnel list, nested forwards included', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/tunnels`]: WIRE_TUNNELS }));
    const tunnels = await ssh.getTunnels();
    assert.equal(tunnels.length, 2);

    const t1 = tunnels[0];
    assert.equal(t1.id, 't-1');
    assert.equal(t1.name, 'Vendor VPN');
    assert.equal(t1.enabled, true);
    assert.equal(t1.port, 22);
    assert.equal(t1.authMethod, 'PASSWORD');
    assert.equal(t1.acceptedHostKeyType, 'ssh-ed25519');
    assert.equal(t1.forwards.length, 2, 'plural nested forwards');
    assert.deepEqual(t1.forwards[0], {
        direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661,
        destinationHost: 'vendor-hl7', destinationPort: 6661
    });
    assert.equal(t1.forwards[1].direction, 'REMOTE');

    const t2 = tunnels[1];
    assert.equal(t2.enabled, false, 'the STRING "false" reads as false');
    assert.equal(t2.verifyHostKey, false);
    assert.equal(t2.port, 2222, 'numeric string coerced');
    assert.equal(t2.serverAliveIntervalSeconds, 15);
    assert.equal(t2.serverAliveCountMax, 5);
    assert.equal(t2.forwards.length, 1, 'singleton-collapsed forwards -> one-element array');
    assert.equal(t2.forwards[0].bindPort, 5432, 'forward port string coerced');
});

test('getTunnels parses a singleton list (bare object) with empty forwards ("")', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/tunnels`]: WIRE_TUNNELS_SINGLETON }));
    const tunnels = await ssh.getTunnels();
    assert.equal(tunnels.length, 1);
    assert.equal(tunnels[0].id, 't-3');
    assert.deepEqual(tunnels[0].forwards, []);
});

test('getTunnels answers [] for an empty list - {"list":""}', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/tunnels`]: '{"list":""}' }));
    assert.deepEqual(await ssh.getTunnels(), []);
});

/* ---- masked secrets round-trip ------------------------------------------------- */

test('SECRET_MASK matches the server constant (SshTunnel.SECRET_MASK)', () => {
    assert.equal(SECRET_MASK, '********');
});

test('masked secrets ride through normalize untouched and serialize back verbatim', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/tunnels`]: WIRE_TUNNELS }));
    const [t1, t2] = await ssh.getTunnels();
    assert.equal(t1.password, SECRET_MASK, 'stored password arrives masked');
    assert.equal(t2.password, '', 'no stored password stays empty');
    assert.equal(t2.privateKeyPem, SECRET_MASK);
    assert.equal(t2.privateKeyPassphrase, SECRET_MASK);

    // Sending the mask back means keep-stored-value — it must survive the XML
    // write path byte-for-byte (and untrimmed).
    const xml = tunnelXml(t2, { includeId: true });
    assert.ok(xml.includes(`<privateKeyPem>${SECRET_MASK}</privateKeyPem>`));
    assert.ok(xml.includes(`<privateKeyPassphrase>${SECRET_MASK}</privateKeyPassphrase>`));
    assert.ok(xml.includes('<password></password>'), 'empty secret stays empty, not masked');
});

test('secrets are never trimmed on the write path', () => {
    const xml = tunnelXml({ name: 'x', password: '  spaced pw  ' });
    assert.ok(xml.includes('<password>  spaced pw  </password>'));
});

/* ---- statuses: numeric-string epochs ------------------------------------------- */

test('getStatuses parses the list and coerces string-typed epoch longs', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/statuses`]: WIRE_STATUSES }));
    const statuses = await ssh.getStatuses();
    assert.equal(statuses.length, 2);

    assert.deepEqual(statuses[0], {
        tunnelId: 't-1', state: 'CONNECTED', lastError: '',
        connectedSince: 1755500000000, failedAttempts: 0, nextRetryAt: 0
    });
    assert.equal(statuses[1].state, 'RECONNECTING');
    assert.equal(statuses[1].connectedSince, 0, '"0" string coerced');
    assert.equal(statuses[1].failedAttempts, 4);
    assert.equal(statuses[1].nextRetryAt, 1755500123456, 'epoch string coerced');
});

test('getStatuses answers [] for an empty list', async () => {
    const ssh = makeApi(fakeApiFor({ [`${EXT}/statuses`]: '{"list":""}' }));
    assert.deepEqual(await ssh.getStatuses(), []);
});

/* ---- events --------------------------------------------------------------------- */

test('getTunnelEvents hits the per-tunnel path and coerces timestamps', async () => {
    const api = fakeApiFor({ [`${EXT}/tunnels/t-1/events`]: WIRE_EVENTS });
    const events = await makeApi(api).getTunnelEvents('t-1');
    assert.equal(api.calls[0].path, `${EXT}/tunnels/t-1/events`);
    assert.equal(events.length, 2);
    assert.deepEqual(events[0], { timestamp: 1755500000000, level: 'INFO', message: 'Connected' });
    assert.equal(events[1].level, 'ERROR');
    assert.equal(events[1].timestamp, 1755500060000);
});

/* ---- diagnostics: steps singleton, missing hint, multi-step --------------------- */

test('testConnection parses a steps singleton whose lone FAIL step has no hint', async () => {
    const api = fakeApiFor({ [`${EXT}/_testConnection`]: WIRE_DIAG_SINGLETON });
    const result = await makeApi(api).testConnection({ id: 't-1', name: 'Vendor VPN' });
    assert.equal(result.success, false, 'the STRING "false" reads as false');
    assert.equal(result.summary, 'Failed at: TCP connect - timeout');
    assert.equal(result.steps.length, 1, 'singleton-collapsed steps -> one-element array');
    assert.deepEqual(result.steps[0], {
        name: 'TCP connect', status: 'FAIL', detail: 'timeout',
        durationMs: 5003, hint: ''
    });
    // The tunnel XML goes WITH its id so the server resolves masked secrets.
    assert.equal(api.calls[0].method, 'POST-XML');
    assert.ok(api.calls[0].xml.startsWith(`<${T_FQCN}><id>t-1</id>`));
});

test('testConnection parses ordered multi-step results, hint included', async () => {
    const api = fakeApiFor({ [`${EXT}/_testConnection`]: WIRE_DIAG });
    const result = await makeApi(api).testConnection({ name: 'unsaved' });
    assert.equal(result.success, true);
    assert.deepEqual(result.steps.map(s => s.status), ['PASS', 'WARN', 'SKIP'], 'step order preserved');
    assert.equal(result.steps[1].hint, 'Fetch and accept the host key.');
    assert.equal(result.steps[1].durationMs, 88, 'duration string coerced');
    assert.ok(!api.calls[0].xml.includes('<id>'), 'unsaved tunnel has no id element');
});

/* ---- host key fetch --------------------------------------------------------------- */

test('fetchHostKey POSTs host/port as QUERY params and parses HostKeyInfo', async () => {
    const api = fakeApiFor({ [`${EXT}/_fetchHostKey`]: WIRE_HOST_KEY });
    const info = await makeApi(api).fetchHostKey('ssh.vendor.example', 22);
    assert.deepEqual(info, {
        keyType: 'ssh-ed25519', fingerprint: 'SHA256:Qz5cAbCd', publicKey: 'AAAAC3NzaC1lZDI1NTE5'
    });
    assert.deepEqual(api.calls[0], {
        method: 'POST', path: `${EXT}/_fetchHostKey`, body: null,
        params: { host: 'ssh.vendor.example', port: 22 }
    });
});

/* ---- plain-string replies ---------------------------------------------------------- */

test('derivePublicKey POSTs tunnel XML and unwraps the {"string":...} reply', async () => {
    const api = fakeApiFor({ [`${EXT}/_derivePublicKey`]: '{"string":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 oie"}' });
    const pub = await makeApi(api).derivePublicKey({ id: 't-2', privateKeyPem: SECRET_MASK });
    assert.equal(pub, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 oie');
    assert.equal(api.calls[0].method, 'POST-XML');
    assert.equal(api.calls[0].path, `${EXT}/_derivePublicKey`);
    assert.ok(api.calls[0].xml.startsWith(`<${T_FQCN}><id>t-2</id>`), 'id rides along for masked-secret resolution');
});

test('revealPrivateKey POSTs to the _revealKey path and returns the plain string', async () => {
    const api = fakeApiFor({
        [`${EXT}/tunnels/t-2/_revealKey`]:
            '{"string":"-----BEGIN OPENSSH PRIVATE KEY-----\\nabc\\n-----END OPENSSH PRIVATE KEY-----"}'
    });
    const pem = await makeApi(api).revealPrivateKey('t-2');
    assert.ok(pem.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'));
    assert.equal(api.calls[0].method, 'POST');
    assert.equal(api.calls[0].path, `${EXT}/tunnels/t-2/_revealKey`);
});

/* ---- normalizer edges ---------------------------------------------------------------- */

test('normalizers reject non-objects and default missing fields to the model defaults', () => {
    assert.equal(normalizeTunnel(null), null);
    assert.equal(normalizeStatus('x'), null);
    assert.equal(normalizeEvent(undefined), null);
    assert.equal(normalizeDiagnosticResult(''), null);
    assert.equal(normalizeHostKeyInfo(0), null);

    const bare = normalizeTunnel({});
    assert.equal(bare.id, null);
    assert.equal(bare.enabled, true, 'model default (enabled = true)');
    assert.equal(bare.port, 22, 'model default');
    assert.equal(bare.authMethod, 'PASSWORD');
    assert.equal(bare.keySource, 'FILE');
    assert.equal(bare.verifyHostKey, true);
    assert.equal(bare.serverAliveIntervalSeconds, 30);
    assert.equal(bare.serverAliveCountMax, 3);
    assert.deepEqual(bare.forwards, []);

    assert.equal(normalizeTunnel({ id: '' }).id, null);
    assert.equal(normalizeTunnel({ id: 7 }).id, '7', 'ids String()-coerced');
    assert.equal(normalizeStatus({}).state, 'DISCONNECTED', 'model default');
    assert.equal(normalizeEvent({}).level, 'INFO', 'model default');
    assert.equal(normalizeDiagnosticResult({}).success, false);
    assert.deepEqual(normalizeDiagnosticResult({ steps: '' }).steps, []);
});

/* ---- tunnelXml: the XStream XML write path -------------------------------------------- */

const XML_TUNNEL = {
    id: 't-1',
    name: 'Vendor <VPN> & Lab',
    enabled: true,
    host: 'ssh.vendor.example',
    port: 22,
    username: 'oie',
    authMethod: 'PASSWORD',
    password: 'p<w>&d',
    keySource: 'FILE',
    privateKeyPath: '',
    privateKeyPem: '',
    privateKeyPassphrase: '',
    verifyHostKey: true,
    acceptedHostKey: 'AAAAC3NzaC1lZDI1NTE5',
    acceptedHostKeyType: 'ssh-ed25519',
    serverAliveIntervalSeconds: 30,
    serverAliveCountMax: 3,
    forwards: [
        { direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: 6661, destinationHost: 'vendor-hl7', destinationPort: 6661 },
        { direction: 'REMOTE', bindHost: '0.0.0.0', bindPort: 9090, destinationHost: '127.0.0.1', destinationPort: 8443 }
    ]
};

const XML_BODY =
    '<name>Vendor &lt;VPN&gt; &amp; Lab</name>'
    + '<enabled>true</enabled>'
    + '<host>ssh.vendor.example</host>'
    + '<port>22</port>'
    + '<username>oie</username>'
    + '<authMethod>PASSWORD</authMethod>'
    + '<password>p&lt;w&gt;&amp;d</password>'
    + '<keySource>FILE</keySource>'
    + '<privateKeyPath></privateKeyPath>'
    + '<privateKeyPem></privateKeyPem>'
    + '<privateKeyPassphrase></privateKeyPassphrase>'
    + '<verifyHostKey>true</verifyHostKey>'
    + '<acceptedHostKey>AAAAC3NzaC1lZDI1NTE5</acceptedHostKey>'
    + '<acceptedHostKeyType>ssh-ed25519</acceptedHostKeyType>'
    + '<serverAliveIntervalSeconds>30</serverAliveIntervalSeconds>'
    + '<serverAliveCountMax>3</serverAliveCountMax>'
    + '<forwards>'
    + `<${F_FQCN}>`
    + '<direction>LOCAL</direction><bindHost>127.0.0.1</bindHost><bindPort>6661</bindPort>'
    + '<destinationHost>vendor-hl7</destinationHost><destinationPort>6661</destinationPort>'
    + `</${F_FQCN}>`
    + `<${F_FQCN}>`
    + '<direction>REMOTE</direction><bindHost>0.0.0.0</bindHost><bindPort>9090</bindPort>'
    + '<destinationHost>127.0.0.1</destinationHost><destinationPort>8443</destinationPort>'
    + `</${F_FQCN}>`
    + '</forwards>';

test('tunnelXml create omits <id> and escapes & < > (golden string)', () => {
    assert.equal(tunnelXml(XML_TUNNEL), `<${T_FQCN}>${XML_BODY}</${T_FQCN}>`);
});

test('tunnelXml update includes <id> (golden string)', () => {
    assert.equal(
        tunnelXml(XML_TUNNEL, { includeId: true }),
        `<${T_FQCN}><id>t-1</id>${XML_BODY}</${T_FQCN}>`);
});

test('tunnelXml defaults missing fields (empty strings, model defaults, empty forwards)', () => {
    const xml = tunnelXml({ name: 'Min' });
    assert.ok(xml.startsWith(`<${T_FQCN}><name>Min</name><enabled>true</enabled>`
        + '<host></host><port>22</port><username></username><authMethod>PASSWORD</authMethod>'));
    assert.ok(xml.endsWith('<serverAliveIntervalSeconds>30</serverAliveIntervalSeconds>'
        + `<serverAliveCountMax>3</serverAliveCountMax><forwards></forwards></${T_FQCN}>`));
    assert.ok(!xml.includes('<id>'), 'no id element without includeId');
});

/* ---- write endpoints: XML bodies, paths ------------------------------------------------ */

test('createTunnel POSTs id-less XStream XML and normalizes the echoed tunnel', async () => {
    const api = fakeApiFor({ [`${EXT}/tunnels`]: WIRE_TUNNEL_ECHO });
    const created = await makeApi(api).createTunnel(XML_TUNNEL);
    assert.deepEqual(api.calls[0], {
        method: 'POST-XML',
        path: `${EXT}/tunnels`,
        xml: `<${T_FQCN}>${XML_BODY}</${T_FQCN}>`,
        params: undefined
    });
    assert.equal(created.id, 't-9', 'server-assigned id read back');
    assert.equal(created.forwards.length, 1, 'echoed singleton forward normalized');
});

test('updateTunnel PUTs XML including <id> to the tunnel path', async () => {
    const api = fakeApiFor({ [`${EXT}/tunnels/t-1`]: WIRE_TUNNEL_ECHO });
    await makeApi(api).updateTunnel('t-1', XML_TUNNEL);
    assert.equal(api.calls[0].method, 'PUT-XML');
    assert.equal(api.calls[0].path, `${EXT}/tunnels/t-1`);
    assert.ok(api.calls[0].xml.startsWith(`<${T_FQCN}><id>t-1</id>`));
});

test('deleteTunnel, startTunnel, and stopTunnel hit the servlet paths', async () => {
    const api = fakeApiFor({});
    const ssh = makeApi(api);
    await ssh.deleteTunnel('t-1');
    await ssh.startTunnel('t-1');
    await ssh.stopTunnel('t-1');
    assert.deepEqual(api.calls[0], { method: 'DELETE', path: `${EXT}/tunnels/t-1` });
    assert.equal(api.calls[1].method, 'POST');
    assert.equal(api.calls[1].path, `${EXT}/tunnels/t-1/_start`);
    assert.equal(api.calls[2].method, 'POST');
    assert.equal(api.calls[2].path, `${EXT}/tunnels/t-1/_stop`);
});

test('createTunnel answers null for a 204 / empty body', async () => {
    const api = fakeApiFor({ [`${EXT}/tunnels`]: null });
    assert.equal(await makeApi(api).createTunnel(XML_TUNNEL), null);
});
