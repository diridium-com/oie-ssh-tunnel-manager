// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * Add/Edit SSH Tunnel overlay — the web port of SshTunnelDialog.
 *
 * Two tabs. Connection: name/enabled, endpoint (host, port, username), the
 * auth block (Password vs Private Key; key from a server-side file path or a
 * pasted PEM, with passphrase), the key helper buttons (Verify Key & Show
 * Public Key via the server's _derivePublicKey, Reveal Stored Key via
 * _revealKey), host-key pinning (verify checkbox with Swing's hard warning on
 * disable, Fetch Host Key -> accept confirm, View with a CLIENT-side SHA-256
 * fingerprint computed exactly like Swing's acceptedFingerprint()), and the
 * keep-alive spinners. Forwards: an editable grid mirroring ForwardTableModel
 * (Direction / Bind Host / Bind Port / Destination Host / Destination Port),
 * row selection + Add Forward / Remove, and the Swing hint line.
 *
 * Secrets: password / PEM / passphrase arrive masked ('********'); they travel
 * through UNTOUCHED (never trimmed) unless the user types a new value —
 * sending the mask back means keep-stored-value. Reveal Stored Key only
 * applies to an already-stored inline key still showing the mask; the server
 * audits every reveal, so the user is warned before the fetch.
 *
 * Ports follow Swing's parsing: ForwardTableModel.parsePort turns bad or
 * blank text into 0, and validation rejects 0 as out of 1-65535. The web
 * number inputs may hold blank/invalid text until Apply for the same reason.
 *
 * Apply runs ssh-core's validateTunnel (the Swing validateLocally chain:
 * required fields, Hosts rules, host-key-accepted guard, port ranges, local
 * bind collisions within the tunnel and against other tunnels), highlights
 * failing fields inline, toasts the first error, and on success calls
 * onApply(value) — the PANEL commits the create/update — then closes.
 * Cancel/Escape close without applying. Test Connection builds the current
 * (unvalidated) candidate and opens the staged diagnostics overlay, which
 * runs the probe itself — Swing's open-first-fill-in-later flow.
 */

import { isMasked, strOf, toArray, validateTunnel } from './ssh-core.js';
import { copyToClipboard, openDiagnostics } from './diagnostic-dialog.jsx';

/* Swing's hard warning on disabling verification, verbatim with the HTML
   markup flattened to text (the <br>s were soft wraps; ui.confirmDialog
   stringifies its message, so bold and paragraph breaks cannot survive). */
const DISABLE_VERIFY_LEAD = 'Turning off host key verification is bad practice for any real connection.';
const DISABLE_VERIFY_REST = 'Without it the engine cannot tell the genuine server from an attacker who'
    + ' intercepts the tunnel, and anything sent through it, including PHI, can be read or altered in'
    + ' transit without detection. This is safe only for throwaway lab testing. For anything else,'
    + ' cancel and click Fetch Host Key instead.';

/* Own classes, NOT host Tailwind utilities: the host generates utilities from
   ITS source scan, so a class no host file uses does not exist in app.css.
   Host COMPONENT classes (.panel, .btn, .tabs, .check, .hint) are fine. */
const DIALOG_CSS = `
.ssht-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100): confirms, alerts, and the
       copyable-text modals (ui.modal / ui.confirmDialog) must stack above. */
    z-index: 95;
}
.ssht-editor {
    width: min(920px, 94vw);
    max-height: 90vh;
    display: flex;
    flex-direction: column;
}
.ssht-editor > .panel-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
}
/* flex:none — the panel-body is a height-constrained flex column and the
   host's .tabs has overflow-y:hidden, so without it an overflowing tab body
   squashes the strip to zero height (tabs invisible + unclickable). */
.ssht-editor .tabs { flex: none; margin: 0 0 12px; }
.ssht-row { flex: none; display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.ssht-row.top { align-items: flex-start; }
.ssht-row > label { flex: none; width: 140px; margin: 0; font-size: 12px; text-align: right; }
.ssht-row.top > label { padding-top: 6px; }
.ssht-field { flex: 1; min-width: 0; }
.ssht-field input[type="text"],
.ssht-field input[type="password"],
.ssht-field select,
.ssht-field textarea { width: 100%; }
/* Compact controls (Swing's "w 100!"/"w 200!"): the host base stylesheet gives
   inputs/selects width:100%, so anything not meant to stretch needs an
   explicit width or it evicts its flex siblings. */
.ssht-editor input.ssht-num { width: 110px; flex: none; }
.ssht-editor select.ssht-sel { width: 200px; flex: none; }
.ssht-pem {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    min-height: 120px;
    white-space: pre;
    overflow: auto;
    resize: vertical;
}
.ssht-keybtns { display: flex; gap: 8px; flex-wrap: wrap; }
.ssht-hostkey { display: flex; align-items: center; gap: 8px; }
.ssht-hk-label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
}
.ssht-hk-label.dim { opacity: 0.5; }
.ssht-hostkey .btn { flex: none; }
.ssht-field.invalid input,
.ssht-field.invalid select,
.ssht-field.invalid textarea {
    border-color: var(--err, #e5484d);
    box-shadow: 0 0 0 1px var(--err, #e5484d);
    border-radius: 4px;
}
.ssht-field-err { color: var(--err, #e5484d); font-size: 11px; margin-top: 2px; }
.ssht-fwd-bar { display: flex; gap: 8px; margin-bottom: 4px; }
.ssht-fwd-scroll { overflow-x: auto; }
.ssht-fwd-head, .ssht-fwd-row {
    display: grid;
    grid-template-columns: 130px minmax(100px, 1fr) 84px minmax(100px, 1fr) 84px;
    gap: 6px;
    align-items: center;
    min-width: 560px;
    padding: 2px 4px;
}
.ssht-fwd-head { font-size: 11px; color: var(--text-dim, #888); margin-top: 8px; }
.ssht-fwd-head > div {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.ssht-fwd-row { margin-bottom: 2px; border-radius: 4px; }
.ssht-fwd-row.sel { background: color-mix(in srgb, var(--accent, #46f) 8%, transparent); }
.ssht-fwd-row input, .ssht-fwd-row select { width: 100%; min-width: 0; }
.ssht-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
`;

/* ---- pure helpers ---------------------------------------------------------- */

// Booleans can arrive as the STRING 'false' on odd wire paths.
function boolOf(v, dflt) {
    if (v === undefined || v === null || v === '') return dflt;
    return String(v) !== 'false';
}

/* Swing's ForwardTableModel.parsePort: trim, blank -> 0, non-integer -> 0.
   Validation then rejects 0 as outside 1-65535. Also used for the top-level
   port and keep-alive fields — a Swing spinner can never hold bad text, so 0
   is a safe "invalid" sentinel the validator catches. */
function parsePort(v) {
    const t = strOf(v).trim();
    if (t === '') return 0;
    if (!/^-?\d+$/.test(t)) return 0;
    return parseInt(t, 10);
}

/* Spinner-style initial text: a finite number renders, anything else falls
   back to the model default (Swing spinners always hold a valid value). */
function numText(v, dflt) {
    const n = Number(v);
    return Number.isFinite(n) ? String(n) : String(dflt);
}

// 0 renders blank, matching ForwardTableModel.getValueAt.
function portText(v) {
    const n = Number(v);
    return Number.isFinite(n) && n !== 0 ? String(n) : '';
}

function isForwardField(field) {
    const f = strOf(field);
    return f === 'forwards' || f.startsWith('forwards.') || f.startsWith('forwards[');
}

/* SHA-256 fingerprint of the base64 wire-format key blob, formatted exactly
   like Swing's acceptedFingerprint() / the server's HostKeyInfo fingerprint:
   "SHA256:" + unpadded base64 of the digest. */
export async function sha256Fingerprint(b64Key) {
    try {
        const bytes = Uint8Array.from(atob(strOf(b64Key).trim()), (c) => c.charCodeAt(0));
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
        // Spread over a fixed 32-byte digest is safe.
        return 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/, '');
    } catch (e) {
        return '(fingerprint unavailable)';
    }
}

/* ---- the dialog ------------------------------------------------------------ */

/* tunnel: normalized tunnel to edit, or null for a new one (a Duplicate is a
   blank-secret copy with id null, passed with an explicit title).
   allTunnels: every normalized tunnel, edited one included — ssh-core's
   validateTunnel owns duplicate-name and bind-collision checks, excluding the
   edited tunnel by id.
   onApply(t): receives the validated tunnel (id preserved when editing, null
   when new); the PANEL commits it — the dialog has already closed, matching
   the Swing dispose-then-save flow.
   Returns { close } so the opener can dismiss it programmatically. */
export function openTunnelEditor(platform, api, { tunnel = null, allTunnels = [], title, onApply } = {}) {
    const React = platform.React;
    const ui = platform.ui;

    const editingId = tunnel && tunnel.id !== undefined && tunnel.id !== null && tunnel.id !== ''
        ? String(tunnel.id) : null;

    let closed = false;
    let mounted = null;
    let diag = null;               // diagnostics overlay opened by Test Connection
    function close() {
        if (closed) return;
        closed = true;
        if (diag) { diag.close(); diag = null; }   // owner-disposes-owned (Swing modality parity)
        if (mounted) {
            mounted.teardown();
            if (mounted.el && mounted.el.parentNode) mounted.el.parentNode.removeChild(mounted.el);
        }
    }

    const msgOf = (e) => String((e && e.message) || e);

    /* Info/warning alert (Swing's JOptionPane message dialogs): titled,
       OK-only, \n kept. */
    function alertDialog(title, message) {
        return new Promise((resolve) => {
            ui.modal({
                title,
                body: ui.h('div', { style: 'white-space: pre-line; overflow-wrap: anywhere; max-width: 560px' }, message),
                onClose: () => resolve(),
                buttons: [{ label: 'OK', primary: true, onClick: () => resolve() }]
            });
        });
    }

    /* Yes/No confirm (Swing's YES_NO_OPTION) — the role-editor precedent. */
    function confirmYesNo(title, message) {
        return new Promise((resolve) => {
            ui.modal({
                title,
                body: ui.h('div', { style: 'white-space: pre-line; overflow-wrap: anywhere; max-width: 560px' }, message),
                onClose: () => resolve(false),
                buttons: [
                    { label: 'No', onClick: () => resolve(false) },
                    { label: 'Yes', primary: true, onClick: () => resolve(true) }
                ]
            });
        });
    }

    /* Swing's showCopyableText: message + selectable monospace block + Copy.
       Copy keeps the modal open (onClick returns false). */
    function showCopyableText(title, message, text) {
        const h = ui.h;
        const body = h('div', { style: 'display: flex; flex-direction: column; gap: 8px; min-width: 440px; max-width: 70vw' },
            h('div', { style: 'white-space: pre-line; font-size: 13px' }, message),
            h('pre', {
                style: 'margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;'
                    + ' border: 1px solid var(--line, #8884); border-radius: 4px; padding: 8px 10px;'
                    + ' max-height: 240px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere;'
                    + ' user-select: text;'
            }, strOf(text)));
        ui.modal({
            title,
            body,
            buttons: [
                { label: 'Copy', onClick: () => { copyToClipboard(ui, text, title); return false; } },
                { label: 'Close', primary: true }
            ]
        });
    }

    function TunnelDialog() {
        const t = tunnel || {};

        // Connection fields (defaults mirror a fresh SshTunnel's initializers).
        const [name, setName] = React.useState(() => strOf(t.name));
        const [enabled, setEnabled] = React.useState(() => boolOf(t.enabled, true));
        const [host, setHost] = React.useState(() => strOf(t.host));
        const [portField, setPortField] = React.useState(() => numText(t.port, 22));
        const [username, setUsername] = React.useState(() => strOf(t.username));
        const [authMethod, setAuthMethod] = React.useState(
            () => (strOf(t.authMethod) === 'PRIVATE_KEY' ? 'PRIVATE_KEY' : 'PASSWORD'));
        // Secrets: initialized to the stored value (possibly the mask), NEVER
        // trimmed, passed through untouched unless retyped.
        const [password, setPassword] = React.useState(() => strOf(t.password));
        const [keySource, setKeySource] = React.useState(
            () => (strOf(t.keySource) === 'INLINE' ? 'INLINE' : 'FILE'));
        const [keyPath, setKeyPath] = React.useState(() => strOf(t.privateKeyPath));
        const [keyPem, setKeyPem] = React.useState(() => strOf(t.privateKeyPem));
        const [passphrase, setPassphrase] = React.useState(() => strOf(t.privateKeyPassphrase));
        const [verifyHostKey, setVerifyHostKey] = React.useState(() => boolOf(t.verifyHostKey, true));
        // Accepted host key: dialog-local until Apply persists it (Swing sets
        // it on the working copy the same way).
        const [acceptedKey, setAcceptedKey] = React.useState(() => strOf(t.acceptedHostKey));
        const [acceptedKeyType, setAcceptedKeyType] = React.useState(() => strOf(t.acceptedHostKeyType));
        const [acceptedFp, setAcceptedFp] = React.useState('');
        const [keepAlive, setKeepAlive] = React.useState(() => numText(t.serverAliveIntervalSeconds, 30));
        const [keepAliveCount, setKeepAliveCount] = React.useState(() => numText(t.serverAliveCountMax, 3));

        // Forwards grid rows (ForwardTableModel: ports render blank when 0).
        const [rows, setRows] = React.useState(() => toArray(t.forwards).map((f) => ({
            direction: strOf(f && f.direction) === 'REMOTE' ? 'REMOTE' : 'LOCAL',
            bindHost: strOf(f && f.bindHost),
            bindPort: portText(f && f.bindPort),
            destinationHost: strOf(f && f.destinationHost),
            destinationPort: portText(f && f.destinationPort)
        })));
        const [selRow, setSelRow] = React.useState(null);

        const [tab, setTab] = React.useState('connection');
        const [errors, setErrors] = React.useState([]);
        const [verifyingKey, setVerifyingKey] = React.useState(false);
        const [revealing, setRevealing] = React.useState(false);
        const [fetching, setFetching] = React.useState(false);

        // Escape cancels (Swing dialog parity) — unless a host modal, a
        // context menu, or a later house overlay (diagnostics) owns the key.
        React.useEffect(() => {
            const onKey = (e) => {
                if (e.key === 'Escape'
                        && !document.querySelector('.modal-overlay')
                        && !document.querySelector('.ctx-surface')
                        // Diagnostics stacked above owns the key.
                        && !document.querySelector('.sshdiag-overlay')) close();
            };
            document.addEventListener('keydown', onKey);
            return () => document.removeEventListener('keydown', onKey);
        }, []);

        // Client-side fingerprint of the accepted key for the status label
        // (Swing's acceptedFingerprint, WebCrypto is async so it fills in).
        React.useEffect(() => {
            let alive = true;
            if (!acceptedKey) { setAcceptedFp(''); return undefined; }
            sha256Fingerprint(acceptedKey).then((fp) => { if (alive) setAcceptedFp(fp); });
            return () => { alive = false; };
        }, [acceptedKey]);

        /* Swing's collectInto(): every field is collected regardless of which
           auth section is visible; name/host/username/path trimmed, secrets
           NEVER trimmed; ports through Swing's parse-bad-to-0. */
        function buildTunnel() {
            return {
                id: editingId,
                name: name.trim(),
                enabled: !!enabled,
                host: host.trim(),
                port: parsePort(portField),
                username: username.trim(),
                authMethod,
                password,
                keySource,
                privateKeyPath: keyPath.trim(),
                privateKeyPem: keyPem,
                privateKeyPassphrase: passphrase,
                verifyHostKey: !!verifyHostKey,
                acceptedHostKey: acceptedKey,
                acceptedHostKeyType: acceptedKeyType,
                // Blank stays blank so the validator's blank->default-30 branch
                // fires (a typed 0 is the legal keep-alive-disabled value).
                serverAliveIntervalSeconds: strOf(keepAlive).trim() === '' ? '' : parsePort(keepAlive),
                serverAliveCountMax: parsePort(keepAliveCount),
                forwards: rows.map((r) => ({
                    direction: r.direction,
                    bindHost: r.bindHost.trim(),
                    bindPort: parsePort(r.bindPort),
                    destinationHost: r.destinationHost.trim(),
                    destinationPort: parsePort(r.destinationPort)
                }))
            };
        }

        /* Verifies the passphrase decrypts the key and shows the public key to
           authorize. Masked secrets resolve server-side against the stored
           tunnel (the candidate carries the id). */
        async function showPublicKey() {
            if (authMethod !== 'PRIVATE_KEY') {
                await alertDialog('Not a key', 'Switch authentication to Private Key first.');
                return;
            }
            const candidate = buildTunnel();
            setVerifyingKey(true);
            try {
                const publicKey = await api.derivePublicKey(candidate);
                showCopyableText('Public Key',
                    'Key verified. Add this line to ~/.ssh/authorized_keys on the SSH server:',
                    strOf(publicKey));
            } catch (e) {
                await alertDialog('Public Key', 'Failed to derive public key: ' + msgOf(e));
            } finally {
                setVerifyingKey(false);
            }
        }

        /* Reveal only applies to an already-stored inline key still showing
           the mask — nothing to reveal for a file-path key, a brand-new
           tunnel, or a key already revealed or retyped. The server audits the
           reveal ("Private Key Revealed" event), so warn before fetching. */
        const revealEnabled = editingId !== null && isMasked(keyPem);
        async function revealStoredKey() {
            if (editingId === null) return;
            // ui.confirmDialog stringifies its message — plain text only.
            const ok = await ui.confirmDialog('Reveal Stored Private Key',
                'The stored private key will be fetched from the server and shown here in plaintext.'
                + ' The server records this action in its event log. Reveal the key?',
                { okLabel: 'Reveal' });
            if (!ok) return;
            setRevealing(true);
            try {
                const pem = await api.revealPrivateKey(editingId);
                if (!pem) {
                    await alertDialog('Nothing to reveal', 'There is no stored inline private key to reveal.');
                } else {
                    setKeyPem(strOf(pem));
                }
            } catch (e) {
                await alertDialog('Reveal Stored Key', 'Failed to reveal private key: ' + msgOf(e));
            } finally {
                setRevealing(false);
            }
        }

        /* Warns hard before letting an admin turn host-key verification off
           (Swing's option dialog, default "Keep verification on"). The
           checkbox is controlled, so an unconfirmed uncheck changes nothing. */
        async function onVerifyToggle(checked) {
            if (checked) {
                setVerifyHostKey(true);
                return;
            }
            // ui.confirmDialog stringifies its message (newlines collapse),
            // so Swing's HTML warning travels as one flat verbatim paragraph.
            const ok = await ui.confirmDialog('Disable host key verification?',
                DISABLE_VERIFY_LEAD + ' ' + DISABLE_VERIFY_REST,
                { danger: true, okLabel: 'Disable anyway' });
            if (ok) setVerifyHostKey(false);
        }

        async function fetchHostKey() {
            const trimmedHost = host.trim();
            if (trimmedHost === '') {
                await alertDialog('Host required', 'Enter the SSH host first.');
                return;
            }
            const port = parsePort(portField);
            setFetching(true);
            try {
                const info = await api.fetchHostKey(trimmedHost, port);
                const keyType = strOf(info && info.keyType);
                const fingerprint = strOf(info && info.fingerprint);
                const ok = await confirmYesNo('Verify Host Key',
                    'Host: ' + trimmedHost + ':' + port + '\nKey type: ' + keyType
                    + '\nFingerprint: ' + fingerprint + '\n\nAccept this host key?');
                if (ok) {
                    setAcceptedKey(strOf(info && info.publicKey));
                    setAcceptedKeyType(keyType);
                }
            } catch (e) {
                await alertDialog('Fetch Host Key', 'Failed to fetch host key: ' + msgOf(e));
            } finally {
                setFetching(false);
            }
        }

        /* View the accepted key: type + CLIENT-side SHA-256 fingerprint (the
           blob is verified locally, not trusted from the server reply) and the
           copyable "<type> <base64>" line. */
        async function viewHostKey() {
            if (!acceptedKey) return;
            const fp = await sha256Fingerprint(acceptedKey);
            showCopyableText('Accepted Host Key',
                'Type: ' + acceptedKeyType + '\nFingerprint: ' + fp
                + '\n\nThis is the key connections are pinned to.',
                acceptedKeyType + ' ' + acceptedKey);
        }

        /* Swing's open-first flow: the diagnostics overlay appears instantly
           in a running state and runs the probe itself. No validation first —
           testing a half-built tunnel is allowed, exactly like Swing. */
        function testConnection() {
            diag = openDiagnostics(platform, api, { tunnel: buildTunnel() });
        }

        function apply() {
            const raw = buildTunnel();
            let result;
            try {
                result = validateTunnel(raw, allTunnels) || {};
            } catch (e) {
                ui.toast(msgOf(e), 'error');
                return;
            }
            const errs = Array.isArray(result.errors) ? result.errors : [];
            if (errs.length > 0) {
                setErrors(errs);
                // Bring the failing field into view — highlights on a hidden
                // tab would look like a dead Apply button.
                setTab(isForwardField(errs[0] && errs[0].field) ? 'forwards' : 'connection');
                ui.toast(strOf(errs[0] && errs[0].message) || 'Validation failed.', 'error');
                return;
            }
            setErrors([]);
            const out = Object.assign({}, result.value || raw);
            out.id = raw.id;
            // Panel commits (create/update) and surfaces engine errors; the
            // dialog is done the moment validation passes (Swing dispose flow).
            if (typeof onApply === 'function') onApply(out);
            close();
        }

        /* Forwards grid ops (ForwardTableModel.addForward/removeForward). */
        function addForward() {
            setRows(rows.concat([{
                direction: 'LOCAL', bindHost: '127.0.0.1', bindPort: '',
                destinationHost: '', destinationPort: ''
            }]));
        }
        function removeForward() {
            if (selRow === null || selRow < 0 || selRow >= rows.length) return;
            setRows(rows.filter((r, i) => i !== selRow));
            setSelRow(null);
        }
        function updateRow(index, patch) {
            setRows(rows.map((r, i) => (i === index ? Object.assign({}, r, patch) : r)));
        }

        /* One label/control row. Plain function, NOT a component — an inline
           component type would remount its inputs (and drop focus) on every
           keystroke. */
        function row(label, fieldKey, control, { top } = {}) {
            const err = fieldKey ? errors.find((e) => e && e.field === fieldKey) : null;
            return (
                <div className={'ssht-row' + (top ? ' top' : '')}>
                    <label>{label}</label>
                    <div className={'ssht-field' + (err ? ' invalid' : '')}>
                        {control}
                        {err ? <div className="ssht-field-err">{strOf(err.message)}</div> : null}
                    </div>
                </div>
            );
        }

        const hostKeyText = acceptedKey
            ? 'Accepted: ' + acceptedKeyType + '  ' + (acceptedFp || '…')
            : 'No host key accepted';

        const forwardErrors = errors.filter((e) => e && isForwardField(e.field));

        const connectionTab = (
            <div>
                {row('Name:', 'name',
                    <input type="text" value={name} autoFocus
                        onChange={(e) => setName(e.target.value)} />)}
                {row('', null,
                    <label className="check">
                        <input type="checkbox" checked={enabled}
                            onChange={(e) => setEnabled(e.target.checked)} />
                        Enabled
                    </label>)}
                {row('SSH Host:', 'host',
                    <input type="text" value={host}
                        onChange={(e) => setHost(e.target.value)} />)}
                {row('SSH Port:', 'port',
                    <input type="number" className="ssht-num" min={1} max={65535} step={1}
                        value={portField} onChange={(e) => setPortField(e.target.value)} />)}
                {/* Integration credentials, not login credentials: autofill and
                    the browser password vault must stay out of every field. */}
                {row('Username:', 'username',
                    <input type="text" value={username} autoComplete="off"
                        onChange={(e) => setUsername(e.target.value)} />)}
                {row('Authentication:', null,
                    <select className="ssht-sel" value={authMethod}
                        onChange={(e) => setAuthMethod(e.target.value)}>
                        <option value="PASSWORD">Password</option>
                        <option value="PRIVATE_KEY">Private Key</option>
                    </select>)}

                {authMethod === 'PASSWORD' ? (
                    row('Password:', 'password',
                        <input type="password" value={password} autoComplete="new-password"
                            onChange={(e) => setPassword(e.target.value)} />)
                ) : (
                    <div>
                        {row('Key Source:', null,
                            <select className="ssht-sel" value={keySource}
                                onChange={(e) => setKeySource(e.target.value)}>
                                <option value="FILE">File on server</option>
                                <option value="INLINE">Pasted key</option>
                            </select>)}
                        {keySource === 'FILE'
                            ? row('Key File Path:', 'privateKeyPath',
                                <input type="text" value={keyPath} autoComplete="off"
                                    onChange={(e) => setKeyPath(e.target.value)} />)
                            : row('Private Key:', 'privateKeyPem',
                                <textarea className="ssht-pem" rows={6} wrap="off"
                                    autoComplete="off" spellCheck={false} value={keyPem}
                                    onChange={(e) => setKeyPem(e.target.value)} />,
                                { top: true })}
                        {row('Passphrase:', 'privateKeyPassphrase',
                            <input type="password" value={passphrase} autoComplete="new-password"
                                onChange={(e) => setPassphrase(e.target.value)} />)}
                        {row('', null,
                            <div className="ssht-keybtns">
                                <button className="btn" disabled={verifyingKey}
                                    onClick={() => showPublicKey()}>
                                    {verifyingKey ? 'Verifying…' : 'Verify Key & Show Public Key'}
                                </button>
                                {keySource === 'INLINE' ? (
                                    <button className="btn" disabled={!revealEnabled || revealing}
                                        title="Fetch the stored private key from the server so you can validate it"
                                        onClick={() => revealStoredKey()}>
                                        {revealing ? 'Revealing…' : 'Reveal Stored Key'}
                                    </button>
                                ) : null}
                            </div>)}
                    </div>
                )}

                {row('Host Key:', 'verifyHostKey',
                    <label className="check">
                        <input type="checkbox" checked={verifyHostKey}
                            onChange={(e) => onVerifyToggle(e.target.checked)} />
                        Verify host key (strongly recommended)
                    </label>)}
                {row('', 'acceptedHostKey',
                    <div className="ssht-hostkey">
                        <span className={'ssht-hk-label' + (verifyHostKey ? '' : ' dim')}
                            title={hostKeyText}>{hostKeyText}</span>
                        <button className="btn" disabled={!acceptedKey}
                            onClick={() => viewHostKey()}>View…</button>
                        <button className="btn" disabled={!verifyHostKey || fetching}
                            onClick={() => fetchHostKey()}>
                            {fetching ? 'Fetching…' : 'Fetch Host Key…'}
                        </button>
                    </div>)}
                {row('', null,
                    <div className="hint">
                        Pins the server's host key so a man-in-the-middle can be detected. Accepting it
                        takes one click. Leave on for any connection carrying PHI.
                    </div>)}

                {row('Keep-alive (sec):', 'serverAliveIntervalSeconds',
                    <input type="number" className="ssht-num" min={0} max={3600} step={5}
                        value={keepAlive} onChange={(e) => setKeepAlive(e.target.value)} />)}
                {row('Keep-alive retries:', 'serverAliveCountMax',
                    <input type="number" className="ssht-num" min={1} max={20} step={1}
                        value={keepAliveCount} onChange={(e) => setKeepAliveCount(e.target.value)} />)}
            </div>
        );

        const forwardsTab = (
            <div>
                <div className="ssht-fwd-bar">
                    <button className="btn" onClick={() => addForward()}>Add Forward</button>
                    <button className="btn" disabled={selRow === null}
                        onClick={() => removeForward()}>Remove</button>
                </div>
                <div className="hint">
                    Local (-L): listens on this engine host. Remote (-R): listens on the SSH server.
                </div>
                <div className="ssht-fwd-scroll">
                    <div className="ssht-fwd-head">
                        <div title="Direction">Direction</div>
                        <div title="Bind Host">Bind Host</div>
                        <div title="Bind Port">Bind Port</div>
                        <div title="Destination Host">Destination Host</div>
                        <div title="Destination Port">Destination Port</div>
                    </div>
                    {rows.map((r, i) => (
                        <div key={i} className={'ssht-fwd-row' + (selRow === i ? ' sel' : '')}
                            onMouseDown={() => setSelRow(i)}
                            onFocusCapture={() => setSelRow(i)}>
                            <select value={r.direction}
                                onChange={(e) => updateRow(i, { direction: e.target.value })}>
                                <option value="LOCAL">Local (-L)</option>
                                <option value="REMOTE">Remote (-R)</option>
                            </select>
                            <input type="text" value={r.bindHost}
                                onChange={(e) => updateRow(i, { bindHost: e.target.value })} />
                            <input type="number" min={1} max={65535} step={1} value={r.bindPort}
                                onChange={(e) => updateRow(i, { bindPort: e.target.value })} />
                            <input type="text" value={r.destinationHost}
                                onChange={(e) => updateRow(i, { destinationHost: e.target.value })} />
                            <input type="number" min={1} max={65535} step={1} value={r.destinationPort}
                                onChange={(e) => updateRow(i, { destinationPort: e.target.value })} />
                        </div>
                    ))}
                    {rows.length === 0 ? <div className="hint">No forwards.</div> : null}
                </div>
                {forwardErrors.length > 0 ? (
                    <div className="ssht-field-err">
                        {forwardErrors.map((e) => strOf(e.message)).join(' ')}
                    </div>
                ) : null}
            </div>
        );

        return (
            <div className="ssht-overlay">
                <style>{DIALOG_CSS}</style>
                <div className="panel ssht-editor">
                    <div className="panel-header">
                        {title || (editingId !== null ? 'Edit SSH Tunnel' : 'New SSH Tunnel')}
                    </div>
                    <div className="panel-body">
                        <div className="tabs">
                            <button className={'tab' + (tab === 'connection' ? ' active' : '')}
                                onClick={() => setTab('connection')}>Connection</button>
                            <button className={'tab' + (tab === 'forwards' ? ' active' : '')}
                                onClick={() => setTab('forwards')}>Forwards</button>
                        </div>
                        {tab === 'connection' ? connectionTab : forwardsTab}
                    </div>
                    <div className="ssht-foot">
                        <button className="btn" onClick={() => testConnection()}>Test Connection</button>
                        <button className="btn" onClick={() => close()}>Cancel</button>
                        <button className="btn btn-primary" onClick={() => apply()}>Apply</button>
                    </div>
                </div>
            </div>
        );
    }

    // Imperative mount: platform.reactView wraps the component with the shell's
    // providers + error boundary and hands back { el, teardown } (the same
    // bridge routed views use); the overlay inside is position:fixed, so the
    // display:contents wrapper parks harmlessly on document.body.
    mounted = platform.reactView(TunnelDialog)({ params: {}, query: {} });
    document.body.appendChild(mounted.el);
    return { close };
}
