// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * Connection Test overlay — the web port of DiagnosticResultDialog +
 * DiagnosticResultPanel.
 *
 * Opens IMMEDIATELY in a running state (summary "Running connection test…"
 * with an indeterminate progress bar, empty step table below) and only then
 * awaits api.testConnection(tunnel) — the staged SSH probe takes several
 * seconds, and a dialog that only appears at the end reads as a hung, broken
 * button (the Swing comment says exactly this). When the DiagnosticResult
 * lands, the step table fills in; when the call itself fails, the summary
 * flips to the could-not-run message and the failure text lands in the detail
 * area (not a diagnostic step), Copy disabled — Swing's showError().
 *
 * Step table: Step / Result / Detail / ms, result text colored per status
 * (green PASS, amber WARN, red FAIL, grey SKIP — Swing's StatusCellRenderer
 * constants as fallbacks under theme tokens). Auto-selects the first step
 * carrying a hint (usually the failure), else the first FAIL/WARN, else the
 * first row. The detail area below shows the selected step's name + detail +
 * hint; Copy copies the HINT when present (often an authorized_keys line),
 * else the detail — DiagnosticResultPanel.copyDetail()'s preference.
 *
 * Escape closes, deferring to a host .modal-overlay or .ctx-surface context
 * menu stacked above (the inspector precedent). Mounted imperatively through
 * platform.reactView appended to document.body, torn down in an idempotent
 * close().
 */

import { strOf, toArray } from './ssh-core.js';

/* Own classes, NOT host Tailwind utilities: the host generates utilities from
   ITS source scan, so a class no host file uses does not exist in app.css.
   Host COMPONENT classes (.panel, .btn, .btn-primary, .dt) are fine. */
const DIALOG_CSS = `
.sshdiag-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100): host modals and toasts stack above. */
    z-index: 95;
}
.sshdiag-dialog {
    width: min(760px, 92vw);
    height: min(520px, 88vh);
    display: flex;
    flex-direction: column;
}
.sshdiag-dialog > .panel-header {
    flex: none;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.sshdiag-dialog > .panel-body {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    padding: 0;
}
.sshdiag-summary {
    flex: none;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 14px;
    border-bottom: 1px solid var(--line, #8884);
}
.sshdiag-summary-text {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 13px;
}
/* Swing's indeterminate JProgressBar (w 140!, h 14!) in the top bar. */
.sshdiag-progress {
    flex: none;
    position: relative;
    width: 140px;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    background: var(--line, #8884);
}
.sshdiag-progress::after {
    content: '';
    position: absolute;
    top: 0; bottom: 0;
    left: -40%;
    width: 40%;
    border-radius: 3px;
    background: var(--accent, #3b82f6);
    animation: sshdiag-slide 1.1s linear infinite;
}
@keyframes sshdiag-slide {
    to { left: 100%; }
}
/* Split: table ~0.62 of the vertical space (Swing's setResizeWeight(0.62)). */
.sshdiag-table-wrap {
    flex: 1 1 62%;
    min-height: 0;
    overflow: auto;
    border-bottom: 1px solid var(--line, #8884);
}
.sshdiag-table-wrap table {
    width: 100%;
    table-layout: fixed;
}
.sshdiag-table-wrap th { white-space: nowrap; }
.sshdiag-table-wrap td {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.sshdiag-col-step { width: 150px; }
.sshdiag-col-result { width: 80px; }
.sshdiag-col-ms { width: 56px; }
.sshdiag-result-cell { text-align: center; }
.sshdiag-ms-cell {
    text-align: right;
    font-variant-numeric: tabular-nums;
}
/* Swing's StatusCellRenderer colors as fallbacks under theme tokens. */
.sshdiag-pass { color: var(--ok, #1b7f2b); }
.sshdiag-warn { color: var(--warn, #b86e00); }
.sshdiag-fail { color: var(--err, #c02828); }
.sshdiag-skip { color: var(--text-dim, #707070); }
.sshdiag-detail {
    flex: 1 1 38%;
    min-height: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 14px;
}
.sshdiag-detail-text {
    flex: 1;
    min-height: 48px;
    max-height: 40vh;
    margin: 0;
    overflow: auto;
    border: 1px solid var(--line, #8884);
    border-radius: 4px;
    padding: 8px 10px;
    font-family: var(--font-mono, monospace);
    font-size: 12px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}
.sshdiag-detail-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
}
.sshdiag-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
`;

/* ---- pure helpers (wire-quirk tolerant) ------------------------------------ */

// Booleans can arrive as STRINGS on odd wire paths; absent -> false, the Java
// field default.
function boolOf(v) {
    return v === true || String(v) === 'true';
}

/* StepStatus enum key, tolerating both the enum name ('WARN') and its display
   form ('Warning'); anything unrecognized falls to SKIP, the Java field
   default. */
function statusKey(v) {
    return { PASS: 'PASS', WARN: 'WARN', WARNING: 'WARN', FAIL: 'FAIL' }[strOf(v).toUpperCase()] || 'SKIP';
}

// StepStatus display names (StepStatus.toString()).
const STATUS_LABEL = { PASS: 'Pass', WARN: 'Warning', FAIL: 'Fail', SKIP: 'Skipped' };
const STATUS_CLASS = { PASS: 'sshdiag-pass', WARN: 'sshdiag-warn', FAIL: 'sshdiag-fail', SKIP: 'sshdiag-skip' };

/* One DiagnosticResult, coerced into plain rows regardless of which wire path
   delivered it. */
function coerceResult(raw) {
    const steps = toArray(raw && raw.steps).map((s) => ({
        name: strOf(s && s.name),
        status: statusKey(s && s.status),
        detail: strOf(s && s.detail),
        durationMs: Number(s && s.durationMs) || 0,
        hint: strOf(s && s.hint)
    }));
    return {
        success: boolOf(raw && raw.success),
        summary: strOf(raw && raw.summary),
        steps
    };
}

/* DiagnosticResultPanel.setResult()'s auto-select: first step carrying a hint
   (usually the failure), else the first FAIL/WARN, else the first row, else
   none. */
function autoSelectIndex(steps) {
    let i = steps.findIndex((s) => s.hint !== '');
    if (i < 0) i = steps.findIndex((s) => s.status === 'FAIL' || s.status === 'WARN');
    if (i < 0 && steps.length > 0) i = 0;
    return i;
}

/* The detail area's composed text (showSelectedDetail): name, then detail,
   then hint, blank-line separated, skipping empties. */
function composeDetail(step) {
    let text = step.name;
    if (step.detail !== '') text += '\n\n' + step.detail;
    if (step.hint !== '') text += '\n\n' + step.hint;
    return text;
}

// 403 reads as a permission problem; 404/501 as plugin-not-installed
// (host ApiError carries .status).
function testErrorMessage(e) {
    const status = e && e.status;
    if (status === 403) {
        return 'You do not have permission to test tunnel connections'
            + ' (the "manageSshTunnels" permission is required).';
    }
    if (status === 404 || status === 501) {
        return 'The OIE SSH Tunnel Manager plugin is not installed on this engine.';
    }
    return String(e && e.message || e);
}

/* Copy to the clipboard with a success/failure toast; shared with the tunnel
   editor (its Copy buttons behave identically). */
export function copyToClipboard(ui, text, what) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
        ui.toast('Clipboard is not available in this browser context.', 'error');
        return;
    }
    navigator.clipboard.writeText(text == null ? '' : String(text)).then(
        () => ui.toast(what + ' copied to clipboard', 'success'),
        (e) => ui.toast('Copy failed: ' + String(e && e.message || e), 'error'));
}

/* ---- the dialog ------------------------------------------------------------- */

/* tunnel: the (possibly unsaved) tunnel config to probe — masked secrets
   resolve against the stored tunnel with the same id on the server.
   Returns { close } so the opener can dismiss it programmatically. */
export function openDiagnostics(platform, api, { tunnel }) {
    const React = platform.React;
    const ui = platform.ui;

    let handle = null;
    let closed = false;
    const close = () => {
        if (closed || !handle) return;   // idempotent: Escape + Close can race
        closed = true;
        handle.teardown();
        handle.el.remove();
    };

    function DiagnosticDialog() {
        // phase: 'running' (probe in flight) | 'done' (result staged) |
        // 'error' (the call itself failed to run — not a diagnostic step).
        const [phase, setPhase] = React.useState('running');
        const [result, setResult] = React.useState(null);
        const [errorText, setErrorText] = React.useState('');
        const [selected, setSelected] = React.useState(-1);

        // Escape closes (Swing dialog parity) — unless a host modal or a
        // context menu (.ctx-surface) is stacked on top, which owns the key.
        React.useEffect(() => {
            const onKey = (e) => {
                if (e.key === 'Escape'
                        && !document.querySelector('.modal-overlay')
                        && !document.querySelector('.ctx-surface')) close();
            };
            document.addEventListener('keydown', onKey);
            return () => document.removeEventListener('keydown', onKey);
        }, []);

        // The probe starts AFTER the dialog is already showing its running
        // state (Swing opens the dialog first, then the SwingWorker fills it
        // in). The alive flag drops a result landing after close().
        React.useEffect(() => {
            let alive = true;
            (async () => {
                try {
                    const raw = await api.testConnection(tunnel);
                    if (!alive) return;
                    if (!raw) throw new Error('Empty diagnostic response from server');
                    const coerced = coerceResult(raw);
                    setResult(coerced);
                    setSelected(autoSelectIndex(coerced.steps));
                    setPhase('done');
                } catch (e) {
                    if (!alive) return;
                    setErrorText(testErrorMessage(e));
                    setPhase('error');
                }
            })();
            return () => { alive = false; };
        }, []);

        const steps = phase === 'done' ? result.steps : [];
        const step = selected >= 0 && selected < steps.length ? steps[selected] : null;

        // Summary line: showRunning / setResult / showError, verbatim.
        const summaryText = phase === 'running'
            ? 'Running connection test…'
            : phase === 'error'
                ? '✗ The connection test could not run.'
                : (result.success ? '✓ ' : '✗ ') + result.summary;

        // Detail area: the selected step's composed text; in the error state
        // the failure message itself (Swing's showError puts it here).
        const detailText = phase === 'error'
            ? errorText
            : step ? composeDetail(step) : '';

        // Copy prefers the hint (often an authorized_keys line), else the
        // detail; disabled when the selected step has neither, and always
        // disabled in the running/error states (Swing parity).
        const copyText = step ? (step.hint !== '' ? step.hint : step.detail) : '';
        const copyEnabled = phase === 'done' && step != null && copyText !== '';

        return (
            <div className="sshdiag-overlay">
                <style>{DIALOG_CSS}</style>
                <div className="panel sshdiag-dialog">
                    <div className="panel-header">Connection Test</div>
                    <div className="panel-body">
                        <div className="sshdiag-summary">
                            <span className="sshdiag-summary-text" title={summaryText}>
                                {summaryText}
                            </span>
                            {phase === 'running' ? <div className="sshdiag-progress" /> : null}
                        </div>

                        <div className="sshdiag-table-wrap">
                            <table className="dt">
                                <thead>
                                    <tr>
                                        <th className="sshdiag-col-step">Step</th>
                                        <th className="sshdiag-col-result">Result</th>
                                        <th>Detail</th>
                                        <th className="sshdiag-col-ms">ms</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {steps.map((s, i) => (
                                        <tr key={i}
                                            className={i === selected ? 'selected' : ''}
                                            style={{ cursor: 'pointer' }}
                                            onClick={() => setSelected(i)}>
                                            <td title={s.name}>{s.name}</td>
                                            <td className={'sshdiag-result-cell ' + STATUS_CLASS[s.status]}>
                                                {STATUS_LABEL[s.status]}
                                            </td>
                                            <td title={s.detail}>{s.detail}</td>
                                            <td className="sshdiag-ms-cell">
                                                {s.durationMs > 0 ? String(s.durationMs) : ''}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        <div className="sshdiag-detail">
                            <pre className="sshdiag-detail-text">{detailText}</pre>
                            <div className="sshdiag-detail-foot">
                                <button className="btn" disabled={!copyEnabled}
                                    onClick={() => copyToClipboard(ui, copyText,
                                        step && step.hint !== '' ? 'Hint' : 'Detail')}>
                                    Copy
                                </button>
                            </div>
                        </div>
                    </div>

                    <div className="sshdiag-foot">
                        <button className="btn btn-primary" onClick={() => close()}>Close</button>
                    </div>
                </div>
            </div>
        );
    }

    // Imperative mount: platform.reactView wraps the component with the shell's
    // providers + error boundary and hands back { el, teardown } (the same
    // bridge routed views use); the overlay inside is position:fixed, so the
    // display:contents wrapper parks harmlessly on document.body.
    handle = platform.reactView(DiagnosticDialog)({ params: {}, query: {} });
    document.body.appendChild(handle.el);
    return { close };
}
