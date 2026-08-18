// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * "SSH Tunnel Manager" settings tab — the web port of SshTunnelSettingsPanel.
 *
 * Top: a single-select table of tunnels joined with their runtime statuses
 * (Name / Endpoint / Forwards / Enabled / Host Key / Status / Uptime /
 * Attempts / Next Retry / Last Error) under the Swing button row: New, Edit,
 * Duplicate, Delete | Enable, Disable | Start, Stop | Refresh. Bottom: the
 * connection-event log with the "This tunnel" / "All tunnels" radio filter.
 * All mutations commit via REST the moment they confirm — the tab never
 * participates in the settings view's Save/dirty tracking (it registers no
 * save() and never calls markDirty), and says so up front via the italic
 * notice.
 *
 * POLLING: Swing polled at the Administrator's own Dashboard refresh-interval
 * preference (default 10s, floor 2s) while the tab was showing. The web
 * administrator has no such preference, so this panel uses a fixed 10s
 * (POLL_INTERVAL_MS below). The poll runs only while the document is visible
 * (visibilitychange — the web equivalent of Swing's hierarchy listener) and
 * stops on unmount. A monotonically increasing refreshSeq drops stale
 * out-of-order results, exactly like Swing's EDT-side seq check. After any
 * mutation (create/update/delete/enable/disable/start/stop) a BURST runs ~8
 * extra refreshes at 2s spacing (~16s of coverage, past the 15s connect
 * timeout) so a Connecting -> Connected transition shows promptly; the burst
 * stops early when the document hides or the panel unmounts.
 *
 * Failure handling mirrors Swing: a status-fetch failure is surfaced ONCE per
 * mount (not on every poll) and the tunnels render as Disconnected until it
 * clears; a tunnels-fetch failure clears the table and toasts; an event-fetch
 * failure is silent (Swing's log.debug).
 */

import {
    fmtUptime, fmtNextRetry, forwardsSummary, endpointLabel, fmtEventTime,
    statusDisplay, hostKeyDisplay, blankSecrets, mergeEvents
} from './ssh-core.js';
import { openTunnelEditor } from './tunnel-dialog.jsx';

// SshTunnelServletInterface.PLUGIN_NAME — the Swing tab name and the task group key.
const TAB_LABEL = 'SSH Tunnel Manager';
const TUNNEL_GROUP = 'settings_SSH Tunnel Manager';

// The web's polling constant (see the header comment): Swing borrowed the
// Dashboard preference, the web pins 10 seconds.
const POLL_INTERVAL_MS = 10000;
// Burst: first extra refresh after 1s, then every 2s, 8 refreshes total —
// Swing's burstRefresh() timings verbatim.
const BURST_INITIAL_MS = 1000;
const BURST_SPACING_MS = 2000;
const BURST_COUNT = 8;

/* Own classes, NOT host Tailwind utilities: the host generates utilities from
   ITS source scan, so a class no host file uses does not exist in app.css.
   Host COMPONENT classes (.panel, .btn, .dt, .text-text-faint) are fine. */
const PANEL_CSS = `
.sshtun-table-wrap { overflow-x: auto; }
.sshtun-table th { cursor: pointer; user-select: none; white-space: nowrap; }
.sshtun-table td { white-space: nowrap; }
.sshtun-arrow { font-size: 9px; opacity: 0.7; margin-left: 3px; }
/* TunnelStatusCellRenderer's exact colors: red 0xC02828, amber 0xB86E00. */
.sshtun-red { color: #c02828; }
.sshtun-amber { color: #b86e00; }
/* Overflow escape for the Last Error cell (and any long text cell). */
.sshtun-ellip { max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
.sshtun-sep { width: 1px; align-self: stretch; margin: 2px 4px; background: var(--line, #8884); }
.sshtun-events-wrap { max-height: 260px; overflow: auto; }
.sshtun-events td { white-space: nowrap; }
.sshtun-msg { max-width: 480px; overflow: hidden; text-overflow: ellipsis; }
.sshtun-scope { display: flex; gap: 12px; align-items: center; font-weight: normal; }
.sshtun-radio { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; cursor: pointer; }
.sshtun-radio input { width: auto; margin: 0; }
`;

// Immediate-commit notice (the cache/rbac panel precedent) — this tab never
// registers a save handler.
const IMMEDIATE_NOTICE =
    'Changes on this tab are applied to the server immediately'
    + ' when you confirm each action. The Save button does not stage changes here.';

/* Sort comparator: strings via case-insensitive collation (Swing's Collator
   default), everything else numerically. */
function cmp(a, b) {
    if (typeof a === 'string' && typeof b === 'string') {
        return a.localeCompare(b, undefined, { sensitivity: 'base' });
    }
    const na = Number(a);
    const nb = Number(b);
    return na === nb ? 0 : (na < nb ? -1 : 1);
}

function toneClass(tone) {
    if (tone === 'red') return 'sshtun-red';
    if (tone === 'amber') return 'sshtun-amber';
    return '';
}

export function registerTunnelPanel(platform, api) {
    const React = platform.React;
    const ui = platform.ui;

    /* REST failures, translated: 403 is a permission problem (named per the
       plugin's own SshTunnelPermissions), 404/501 means the server-side plugin
       is missing; anything else keeps its message. idScoped: the call targeted
       a tunnel id, so a 404 means THAT tunnel is gone (deleted by another
       admin), not that the plugin is missing. */
    function errText(e, idScoped) {
        const status = e && e.status;
        if (status === 403) {
            return 'permission denied (your role needs the "viewSshTunnels" / "manageSshTunnels" permission)';
        }
        if (status === 404 && idScoped) {
            return 'the tunnel no longer exists on the server';
        }
        if (status === 404 || status === 501) {
            return 'the SSH Tunnel Manager plugin does not appear to be installed on this server';
        }
        return String(e && e.message || e);
    }

    /* TunnelTableModel's ten columns, 1:1, in Swing's order. Every value is a
       string and Swing left-aligns them all (no Long columns here), so no
       numeric alignment classes. Formats and tones come from ssh-core; only
       the exceptions are colored (Failed status red, Unverified host key
       amber — TunnelStatusCellRenderer). Uptime/Attempts/Next Retry render ''
       without a status, matching the model's null-status branches; the
       CONNECTED gate on Uptime is the model's uptimeText() check. Columns
       sort on their displayed value unless a `sort` key says otherwise (the
       time/count columns sort on the raw numbers). */
    const COLUMNS = [
        {
            key: 'name', label: 'Name',
            value: (t) => t.name
        },
        {
            key: 'endpoint', label: 'Endpoint',
            value: (t) => endpointLabel(t)
        },
        {
            key: 'forwards', label: 'Forwards',
            value: (t) => forwardsSummary(t.forwards)
        },
        {
            key: 'enabled', label: 'Enabled',
            value: (t) => (t.enabled ? 'Yes' : 'No')
        },
        {
            key: 'hostKey', label: 'Host Key',
            value: (t) => hostKeyDisplay(t).text,
            tone: (t) => hostKeyDisplay(t).tone
        },
        {
            key: 'status', label: 'Status',
            value: (t, s) => statusDisplay(t, s).text,
            tone: (t, s) => statusDisplay(t, s).tone
        },
        {
            key: 'uptime', label: 'Uptime',
            value: (t, s, now) => (s && s.state === 'CONNECTED' && Number(s.connectedSince) > 0
                ? fmtUptime(Number(s.connectedSince), now) : ''),
            sort: (t, s) => (s && s.state === 'CONNECTED' ? Number(s.connectedSince) || 0 : 0)
        },
        {
            key: 'attempts', label: 'Attempts',
            value: (t, s) => (s && Number(s.failedAttempts) > 0 ? String(s.failedAttempts) : ''),
            sort: (t, s) => (s ? Number(s.failedAttempts) || 0 : 0)
        },
        {
            key: 'nextRetry', label: 'Next Retry',
            value: (t, s, now) => (s && Number(s.nextRetryAt) > 0
                ? fmtNextRetry(Number(s.nextRetryAt), now) : ''),
            sort: (t, s) => (s ? Number(s.nextRetryAt) || 0 : 0)
        },
        {
            key: 'lastError', label: 'Last Error', ellipsis: true,
            value: (t, s) => (s && s.lastError ? String(s.lastError) : '')
        }
    ];

    function TunnelPanel({ setTasks }) {
        const [tunnels, setTunnels] = React.useState([]);
        const [statusMap, setStatusMap] = React.useState({});   // String(tunnelId) -> status
        // Last fetched event lists, names captured at fetch time (like Swing's
        // diagnostics pane keeping the maps it was last pushed):
        // [{ tunnelId, tunnelName, events }]
        const [eventLists, setEventLists] = React.useState([]);
        const [selectedId, setSelectedId] = React.useState(null);
        const [eventScope, setEventScope] = React.useState('this'); // Swing default: "This tunnel"
        const [sortKey, setSortKey] = React.useState(null);     // null = server order (Swing's initial view)
        const [sortDir, setSortDir] = React.useState(1);        // 1 asc, -1 desc
        const [loading, setLoading] = React.useState(true);

        // Refs the stable refresh() reads so the poll/burst timers never see
        // stale closures.
        const seqRef = React.useRef(0);
        const statusErrorShownRef = React.useRef(false);        // Swing's statusErrorShown: once per mount
        const tunnelsErrorShownRef = React.useRef(false);       // auto-poll outages surface once, not per tick
        const mountedRef = React.useRef(true);
        const selectedIdRef = React.useRef(null);
        const eventScopeRef = React.useRef('this');
        const pollRef = React.useRef(null);
        const burstRef = React.useRef(null);

        React.useEffect(() => () => { mountedRef.current = false; }, []);

        // The imperatively mounted tunnel-editor overlay outlives nothing:
        // close it if the settings view unmounts underneath it (route change).
        // close() is idempotent.
        const overlayRef = React.useRef(null);
        React.useEffect(() => () => {
            if (overlayRef.current) overlayRef.current.close();
        }, []);

        /* One refresh = Swing's doRefresh SwingWorker: getTunnels + getStatuses
           in parallel, then the event log for the selected tunnel — or one
           getTunnelEvents call PER tunnel, sequentially (not Promise.all, to
           avoid hammering the server), when the "All tunnels" filter is on.
           refreshSeq drops any result a newer refresh has since obsoleted. */
        // `manual === true` only from the Refresh buttons — auto ticks pass
        // nothing, and the strict compare guards against refresh being wired
        // directly as an event handler someday (first arg = click event).
        const refresh = React.useCallback(async (manual) => {
            const seq = ++seqRef.current;
            const wantedId = selectedIdRef.current;
            const allEvents = eventScopeRef.current === 'all';

            const [tunnelsRes, statusRes] = await Promise.allSettled([
                api.getTunnels(),
                api.getStatuses()
            ]);
            if (seq !== seqRef.current) return;

            if (tunnelsRes.status === 'rejected') {
                // Swing clears the table (and statuses) and alerts; the event
                // pane keeps whatever it was last pushed. Auto-poll failures
                // surface ONCE per outage — the host error toast demands an
                // acknowledgement, and a 10s poll would stack one per tick.
                setTunnels([]);
                setStatusMap({});
                setLoading(false);
                if (manual === true || !tunnelsErrorShownRef.current) {
                    tunnelsErrorShownRef.current = true;
                    ui.toast(`Failed to load tunnels: ${errText(tunnelsRes.reason)}`, 'error');
                }
                return;
            }
            tunnelsErrorShownRef.current = false;   // outage over: the next failure is news again
            const freshTunnels = tunnelsRes.value;
            // Swing parity: refreshData's structural change clears the JTable
            // selection when the selected tunnel disappears — stop polling a
            // deleted tunnel's events.
            const selectionAlive = wantedId != null
                && freshTunnels.some((t) => String(t.id) === String(wantedId));
            if (wantedId != null && !selectionAlive) {
                selectedIdRef.current = null;
                setSelectedId(null);
            }

            let freshStatuses = {};
            let statusError = null;
            if (statusRes.status === 'fulfilled') {
                for (const s of statusRes.value) {
                    freshStatuses[String(s.tunnelId)] = s;
                }
            } else {
                // Without statuses every tunnel renders as Disconnected (the
                // no-status fallback) — surface the real error so it's
                // diagnosable, but only once, not on every poll.
                statusError = statusRes.reason;
            }

            // Event fetch. One try around the whole thing, silent on failure
            // (Swing's log.debug) — a mid-loop failure keeps what was fetched.
            const fetched = {};
            try {
                if (allEvents) {
                    for (const t of freshTunnels) {
                        fetched[String(t.id)] = await api.getTunnelEvents(t.id);
                        if (seq !== seqRef.current) return;
                    }
                } else if (selectionAlive) {
                    fetched[String(wantedId)] = await api.getTunnelEvents(wantedId);
                }
            } catch (e) {
                // Silent: the event pane just keeps rendering what it has.
            }
            if (seq !== seqRef.current) return;

            const names = {};
            for (const t of freshTunnels) names[String(t.id)] = t.name;

            setTunnels(freshTunnels);
            setStatusMap(freshStatuses);
            setEventLists(Object.keys(fetched).map((id) => ({
                tunnelId: id,
                // Swing's names.getOrDefault(id, id)
                tunnelName: names[id] !== undefined ? names[id] : id,
                events: fetched[id]
            })));
            setLoading(false);

            if (statusError && !statusErrorShownRef.current) {
                statusErrorShownRef.current = true;
                ui.toast('Could not load tunnel status (tunnels will show as Disconnected'
                    + ` until this is fixed): ${errText(statusError)}`, 'error');
            }
        }, []);

        /* Burst engine — Swing's burstRefresh(): after a state-changing action
           the server connects/disconnects asynchronously, so refresh a few
           extra times over the next several seconds. Not an always-on fast
           poll; it stops on its own, and early when the document hides or the
           panel unmounts. */
        function stopBurst() {
            const b = burstRef.current;
            if (b) {
                clearTimeout(b.timeoutId);
                clearInterval(b.intervalId);
                burstRef.current = null;
            }
        }
        function burstRefresh() {
            stopBurst();
            const state = { timeoutId: 0, intervalId: 0, remaining: BURST_COUNT };
            const tick = () => {
                if (!mountedRef.current || document.hidden || --state.remaining < 0) {
                    stopBurst();
                    return;
                }
                refresh();
            };
            state.timeoutId = setTimeout(() => {
                tick();
                state.intervalId = setInterval(tick, BURST_SPACING_MS);
            }, BURST_INITIAL_MS);
            burstRef.current = state;
        }

        // Poll while visible; stop when the document hides and on unmount
        // (Swing's hierarchy listener + stopPolling stopping both timers).
        React.useEffect(() => {
            function startPolling() {
                if (pollRef.current == null) {
                    refresh(); // Swing's initial-delay-0 timer does the first fetch
                    pollRef.current = setInterval(refresh, POLL_INTERVAL_MS);
                }
            }
            function stopPolling() {
                if (pollRef.current != null) {
                    clearInterval(pollRef.current);
                    pollRef.current = null;
                }
                stopBurst();
            }
            function onVisibility() {
                if (document.hidden) {
                    stopPolling();
                } else {
                    startPolling();
                }
            }
            document.addEventListener('visibilitychange', onVisibility);
            if (!document.hidden) startPolling();
            return () => {
                document.removeEventListener('visibilitychange', onVisibility);
                stopPolling();
            };
        }, [refresh]);

        React.useEffect(() => {
            // Refresh is the ONLY rail task — no Save participation (the panel
            // never calls setSave, so it can't trip the settings dirty tracking).
            setTasks('SSH Tunnel Manager Tasks', [
                ui.taskButton('Refresh', 'refresh', () => refresh(true), { task: 'doRefresh', group: TUNNEL_GROUP })
            ]);
        }, [refresh, setTasks]);

        const canManage = platform.checkTask(TUNNEL_GROUP, 'doSave');
        const selected = tunnels.find((t) => String(t.id) === String(selectedId)) || null;

        // Client-side sort; sortKey null keeps server order (Swing's initial view).
        const rows = React.useMemo(() => {
            const out = tunnels.map((t) => ({ tunnel: t, status: statusMap[String(t.id)] || null }));
            if (sortKey) {
                const col = COLUMNS.find((c) => c.key === sortKey);
                if (col) {
                    const key = col.sort || col.value;
                    out.sort((a, b) => sortDir * cmp(key(a.tunnel, a.status), key(b.tunnel, b.status)));
                }
            }
            return out;
        }, [tunnels, statusMap, sortKey, sortDir]);
        const now = Date.now();

        // Merged event rows, newest-first. "This tunnel" with no selection
        // shows nothing (Swing's null-selectedTunnelId branch). Switching the
        // radio re-renders from the cached lists only; the next poll widens or
        // narrows the fetch — exactly Swing's radio listeners.
        const eventRows = React.useMemo(() => {
            if (eventScope === 'all') return mergeEvents(eventLists, null);
            if (selectedId == null) return [];
            return mergeEvents(eventLists, String(selectedId));
        }, [eventLists, eventScope, selectedId]);

        function toggleSort(key) {
            if (sortKey === key) {
                setSortDir((d) => -d);
            } else {
                setSortKey(key);
                setSortDir(1);
            }
        }

        // Swing's onSelectionChanged: show the selection immediately from
        // cached data, then refresh so the newly selected tunnel's event log
        // fills in.
        function selectRow(t) {
            const id = String(t.id);
            if (String(selectedId) === id) return;
            selectedIdRef.current = id;
            setSelectedId(id);
            refresh();
        }

        function setScope(scope) {
            eventScopeRef.current = scope;
            setEventScope(scope);
        }

        // Every mutation: commit, surface engine errors as a toast, always
        // reload, and burst so the async connect/disconnect shows promptly.
        async function mutate(call, failMsg, idScoped) {
            try {
                await call();
            } catch (e) {
                ui.toast(`${failMsg}: ${errText(e, idScoped)}`, 'error');
            } finally {
                // A mutation settling after unmount must not re-arm timers
                // (zombie burst nothing can cancel) — Swing's isShowing() check.
                if (mountedRef.current) {
                    refresh();
                    burstRefresh();
                }
            }
        }

        function newTunnel() {
            if (!canManage) return;
            overlayRef.current = openTunnelEditor(platform, api, {
                tunnel: null,
                allTunnels: tunnels,
                onApply: (t) => mutate(() => api.createTunnel(t), 'Failed to create tunnel')
            });
        }

        function editTunnel(t) {
            const target = t || selected;
            if (!target || !canManage) return;
            overlayRef.current = openTunnelEditor(platform, api, {
                tunnel: target,
                allTunnels: tunnels,
                onApply: (u) => mutate(() => api.updateTunnel(target.id, u), 'Failed to update tunnel', true)
            });
        }

        function duplicateTunnel() {
            if (!selected || !canManage) return;
            // Swing: copy, id null, name + " (copy)", secrets blanked — the
            // source came from getTunnels() so its secrets are the mask string;
            // blank them so the admin re-enters real secrets for the new
            // tunnel. Opened as a NEW tunnel (committed via create).
            const copy = blankSecrets({
                ...selected,
                id: null,
                name: `${selected.name} (copy)`,
                forwards: (selected.forwards || []).map((f) => ({ ...f }))
            });
            overlayRef.current = openTunnelEditor(platform, api, {
                tunnel: copy,
                allTunnels: tunnels,
                title: 'Duplicate SSH Tunnel',
                onApply: (t) => mutate(() => api.createTunnel(t), 'Failed to create tunnel')
            });
        }

        async function deleteTunnel() {
            if (!selected || !canManage) return;
            const ok = await ui.confirmDialog('Confirm Delete',
                `Delete tunnel '${selected.name}'? It will be stopped immediately.`,
                { danger: true, okLabel: 'Delete' });
            if (!ok) return;
            await mutate(() => api.deleteTunnel(selected.id), 'Failed to delete tunnel', true);
        }

        /* Flips the enabled attribute of the selected tunnel and saves it.
           Masked secrets pass through unchanged — the server resolves the mask
           against the stored values. */
        function setEnabledState(enable) {
            if (!selected || !canManage || Boolean(selected.enabled) === enable) return;
            const updated = { ...selected, enabled: enable };
            mutate(() => api.updateTunnel(selected.id, updated),
                enable ? 'Failed to enable tunnel' : 'Failed to disable tunnel', true);
        }

        // Start/Stop gate only on a selection, like Swing's updateButtonStates
        // (btnStart/btnStop.setEnabled(selected)).
        function runControl(start) {
            if (!selected || !canManage) return;
            mutate(() => (start ? api.startTunnel(selected.id) : api.stopTunnel(selected.id)),
                start ? 'Failed to start tunnel' : 'Failed to stop tunnel', true);
        }

        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <style>{PANEL_CSS}</style>
                <div className="text-text-faint" style={{ fontStyle: 'italic', fontSize: 12 }}>
                    {IMMEDIATE_NOTICE}
                </div>

                <div className="panel">
                    <div className="panel-header">Tunnels
                        <div className="panel-tools" style={{ display: 'flex', gap: 8 }}>
                            {canManage ? (
                                <>
                                    <button className="btn" onClick={() => newTunnel()}>New</button>
                                    <button className="btn" disabled={!selected} onClick={() => editTunnel()}>Edit</button>
                                    <button className="btn" disabled={!selected} onClick={() => duplicateTunnel()}>Duplicate</button>
                                    <button className="btn" disabled={!selected} onClick={() => deleteTunnel()}>Delete</button>
                                    <span className="sshtun-sep" />
                                    <button className="btn" disabled={!selected || Boolean(selected.enabled)}
                                        onClick={() => setEnabledState(true)}>Enable</button>
                                    <button className="btn" disabled={!selected || !selected.enabled}
                                        onClick={() => setEnabledState(false)}>Disable</button>
                                    <span className="sshtun-sep" />
                                    <button className="btn" disabled={!selected} onClick={() => runControl(true)}>Start</button>
                                    <button className="btn" disabled={!selected} onClick={() => runControl(false)}>Stop</button>
                                    <span className="sshtun-sep" />
                                </>
                            ) : null}
                            <button className="btn" title="Reload tunnels and status now"
                                onClick={() => refresh(true)}>Refresh</button>
                        </div>
                    </div>
                    <div className="panel-body flush">
                        <div className="sshtun-table-wrap">
                            <table className="dt sshtun-table" style={{ width: '100%' }}>
                                <thead>
                                    <tr>
                                        {COLUMNS.map((col) => (
                                            <th key={col.key} onClick={() => toggleSort(col.key)}>
                                                {col.label}
                                                {sortKey === col.key ? (
                                                    <span className="sshtun-arrow">
                                                        {sortDir === 1 ? '▲' : '▼'}
                                                    </span>
                                                ) : null}
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {tunnels.length === 0 ? (
                                        <tr><td colSpan={COLUMNS.length} className="text-text-faint" style={{ padding: 12 }}>
                                            {loading ? 'Loading…' : 'No tunnels defined'}
                                        </td></tr>
                                    ) : rows.map((row) => (
                                        <tr key={String(row.tunnel.id)}
                                            className={String(row.tunnel.id) === String(selectedId) ? 'selected' : ''}
                                            style={{ cursor: 'pointer' }}
                                            onClick={() => selectRow(row.tunnel)}
                                            onDoubleClick={() => { selectRow(row.tunnel); editTunnel(row.tunnel); }}>
                                            {COLUMNS.map((col) => {
                                                const text = col.value(row.tunnel, row.status, now);
                                                const cls = [
                                                    col.tone ? toneClass(col.tone(row.tunnel, row.status)) : '',
                                                    col.ellipsis ? 'sshtun-ellip' : ''
                                                ].filter(Boolean).join(' ');
                                                return (
                                                    <td key={col.key} className={cls}
                                                        title={col.ellipsis && text ? text : undefined}>
                                                        {text}
                                                    </td>
                                                );
                                            })}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-header">Event Log
                        <div className="panel-tools sshtun-scope">
                            <label className="sshtun-radio">
                                <input type="radio" name="sshtun-scope"
                                    checked={eventScope === 'this'}
                                    onChange={() => setScope('this')} />
                                This tunnel
                            </label>
                            <label className="sshtun-radio">
                                <input type="radio" name="sshtun-scope"
                                    checked={eventScope === 'all'}
                                    onChange={() => setScope('all')} />
                                All tunnels
                            </label>
                        </div>
                    </div>
                    <div className="panel-body flush">
                        <div className="sshtun-events-wrap">
                            <table className="dt sshtun-events" style={{ width: '100%' }}>
                                <thead>
                                    <tr>
                                        <th style={{ width: 80 }}>Time</th>
                                        <th style={{ width: 150 }}>Tunnel</th>
                                        <th style={{ width: 60 }}>Level</th>
                                        <th>Message</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {eventRows.length === 0 ? (
                                        <tr><td colSpan={4} className="text-text-faint" style={{ padding: 12 }}>
                                            {eventScope === 'this' && !selected
                                                ? 'Select a tunnel to see its event log'
                                                : 'No events'}
                                        </td></tr>
                                    ) : eventRows.map((row, i) => (
                                        /* Level and Message stay plain — Swing's event
                                           table uses a bare JTable with no cell
                                           renderer, so nothing here is colored. */
                                        <tr key={i}>
                                            <td>{fmtEventTime(Number(row.timestamp))}</td>
                                            <td>{row.tunnelName}</td>
                                            <td>{String(row.level || '')}</td>
                                            <td className="sshtun-msg" title={row.message ? String(row.message) : undefined}>
                                                {row.message}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    platform.registerSettingsPanel({ label: TAB_LABEL, component: TunnelPanel });
}
