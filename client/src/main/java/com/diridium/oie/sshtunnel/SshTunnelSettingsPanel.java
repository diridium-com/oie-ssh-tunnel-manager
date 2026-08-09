/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.event.HierarchyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.prefs.Preferences;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.Timer;

import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.client.ui.Mirth;
import com.mirth.connect.client.ui.PlatformUI;
import com.mirth.connect.client.ui.components.MirthTable;

import net.miginfocom.swing.MigLayout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Settings panel: a live split view of the tunnel list (top) and a diagnostics
 * pane (bottom). Polls at the Administrator's Dashboard interval while showing,
 * stepping up to a few seconds while a tunnel is selected so the operator can
 * watch it in near-real-time.
 */
public class SshTunnelSettingsPanel extends AbstractSettingsPanel {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelSettingsPanel.class);

    private SshTunnelServletInterface servlet;
    private MirthTable table;
    private TunnelTableModel tableModel;
    private TunnelDiagnosticsPane diagnosticsPane;
    private Timer pollTimer;
    private Timer burstTimer;

    private JButton btnEdit;
    private JButton btnDuplicate;
    private JButton btnDelete;
    private JButton btnEnable;
    private JButton btnDisable;
    private JButton btnStart;
    private JButton btnStop;

    private Map<String, SshTunnelStatus> latestStatuses = Map.of();
    /** EDT-only: bumped per refresh so a slow worker's result can't clobber a newer one. */
    private long refreshSeq;
    /** Show a status-fetch failure once, not on every poll. */
    private boolean statusErrorShown;

    public SshTunnelSettingsPanel(String tabName) {
        super(tabName);
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        tableModel = new TunnelTableModel();
        table = new MirthTable();
        table.setModel(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        var statusRenderer = new TunnelStatusCellRenderer();
        table.getColumnModel().getColumn(TunnelTableModel.COL_HOST_KEY).setCellRenderer(statusRenderer);
        table.getColumnModel().getColumn(TunnelTableModel.COL_STATUS).setCellRenderer(statusRenderer);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onSelectionChanged();
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRowCount() == 1) {
                    editTunnel();
                }
            }
        });

        var btnNew = new JButton("New");
        btnNew.addActionListener(e -> newTunnel());
        btnEdit = disabled(new JButton("Edit"), e -> editTunnel());
        btnDuplicate = disabled(new JButton("Duplicate"), e -> duplicateTunnel());
        btnDelete = disabled(new JButton("Delete"), e -> deleteTunnel());
        btnEnable = disabled(new JButton("Enable"), e -> setEnabledState(true));
        btnDisable = disabled(new JButton("Disable"), e -> setEnabledState(false));
        btnStart = disabled(new JButton("Start"), e -> runControl(true));
        btnStop = disabled(new JButton("Stop"), e -> runControl(false));
        var btnRefresh = new JButton("Refresh");
        btnRefresh.setToolTipText("Reload tunnels and status now");
        btnRefresh.addActionListener(e -> doRefresh());

        var buttonPanel = new JPanel(new MigLayout("insets 0 12 0 12", "[][][][]push[][]12[][]12[]", ""));
        buttonPanel.add(btnNew);
        buttonPanel.add(btnEdit);
        buttonPanel.add(btnDuplicate);
        buttonPanel.add(btnDelete);
        buttonPanel.add(btnEnable);
        buttonPanel.add(btnDisable);
        buttonPanel.add(btnStart);
        buttonPanel.add(btnStop);
        buttonPanel.add(btnRefresh);

        var topPanel = new JPanel(new BorderLayout());
        topPanel.add(buttonPanel, BorderLayout.NORTH);
        topPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        diagnosticsPane = new TunnelDiagnosticsPane();

        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topPanel, diagnosticsPane);
        split.setResizeWeight(0.6);
        split.setOneTouchExpandable(true);
        add(split, BorderLayout.CENTER);

        // Poll only while the tab is actually on screen (mirrors the engine's StatusUpdater).
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0) {
                if (isShowing()) {
                    startPolling();
                } else {
                    stopPolling();
                }
            }
        });
    }

    private JButton disabled(JButton button, java.awt.event.ActionListener action) {
        button.setEnabled(false);
        button.addActionListener(action);
        return button;
    }

    private void startPolling() {
        if (pollTimer == null) {
            pollTimer = new Timer(currentIntervalMs(), e -> doRefresh());
            pollTimer.setRepeats(true);
            pollTimer.setInitialDelay(0);
        }
        pollTimer.setDelay(currentIntervalMs());
        // Idempotent: only (re)start if not already running, so this can be
        // called from both the framework's doRefresh and the hierarchy listener
        // without doubling up. The initial-delay-0 timer does the first fetch.
        if (!pollTimer.isRunning()) {
            pollTimer.start();
        }
    }

    private void stopPolling() {
        if (pollTimer != null) {
            pollTimer.stop();
        }
        if (burstTimer != null) {
            burstTimer.stop();
        }
    }

    /**
     * After a state-changing action (start/stop/enable/disable/save), the server
     * connects or disconnects asynchronously, so the result isn't ready on the
     * immediate refresh. Refresh a few more times over the next several seconds so
     * a Connecting -> Connected transition shows promptly instead of waiting for
     * the next full poll interval. Not an always-on fast poll; it stops on its own.
     */
    private void burstRefresh() {
        if (burstTimer != null) {
            burstTimer.stop();
        }
        var remaining = new int[] {8}; // ~16s of coverage, past the 15s connect timeout
        burstTimer = new Timer(2000, null);
        burstTimer.setInitialDelay(1000);
        burstTimer.addActionListener(e -> {
            if (!isShowing() || --remaining[0] < 0) {
                burstTimer.stop();
                return;
            }
            doRefresh();
        });
        burstTimer.start();
    }

    /** The Administrator's own Dashboard refresh interval; no plugin-specific rate. */
    private int currentIntervalMs() {
        try {
            int seconds = Preferences.userNodeForPackage(Mirth.class).getInt("intervalTime", 10);
            return Math.max(2, seconds) * 1000;
        } catch (Exception e) {
            return 10000;
        }
    }

    private void onSelectionChanged() {
        updateButtonStates();
        var selected = selectedTunnel();
        // Show the selection immediately from cached data; the selected tunnel's
        // event log fills in on the next refresh (auto or manual).
        diagnosticsPane.setSelectedTunnel(selected);
        if (isShowing()) {
            doRefresh();
        }
    }

    @Override
    public void doRefresh() {
        // Mirth calls this when the tab is shown; use it as a reliable trigger to
        // start the live poll, in case the hierarchy listener hasn't fired yet.
        if (isShowing()) {
            startPolling();
        }
        var selected = selectedTunnel();
        boolean allEvents = diagnosticsPane.isShowingAllTunnels();
        final long seq = ++refreshSeq;
        new SwingWorker<Void, Void>() {
            private List<SshTunnel> tunnels;
            private Map<String, SshTunnelStatus> statusMap;
            private Map<String, String> names;
            private Map<String, List<TunnelEvent>> events;
            private Exception statusError;

            @Override
            protected Void doInBackground() throws Exception {
                tunnels = getServlet().getTunnels();
                statusMap = new HashMap<>();
                try {
                    for (var status : getServlet().getStatuses()) {
                        statusMap.put(status.getTunnelId(), status);
                    }
                } catch (Exception e) {
                    // A silent failure here makes every tunnel look "Disconnected"
                    // (the no-status fallback). Capture it so done() can surface
                    // the real exception instead of hiding it behind a grey status.
                    statusError = e;
                    log.warn("Could not fetch tunnel statuses; tunnels will show as disconnected", e);
                }
                names = new LinkedHashMap<>();
                for (var tunnel : tunnels) {
                    names.put(tunnel.getId(), tunnel.getName());
                }
                events = new HashMap<>();
                try {
                    if (allEvents) {
                        for (var tunnel : tunnels) {
                            events.put(tunnel.getId(), getServlet().getTunnelEvents(tunnel.getId()));
                        }
                    } else if (selected != null) {
                        events.put(selected.getId(), getServlet().getTunnelEvents(selected.getId()));
                    }
                } catch (Exception e) {
                    log.debug("Could not fetch tunnel events", e);
                }
                return null;
            }

            @Override
            protected void done() {
                // A newer refresh has since started; drop this stale result so it
                // can't overwrite fresher data (SwingWorker.done order is not
                // start order).
                if (seq != refreshSeq) {
                    return;
                }
                try {
                    get();
                    latestStatuses = statusMap;
                    // Preserve selection: only reselect if the poll actually
                    // rebuilt the table (tunnels added/removed/reordered).
                    if (tableModel.refreshData(tunnels, statusMap)) {
                        reselect(selected);
                    }
                    diagnosticsPane.setEventData(names, events);
                    diagnosticsPane.setSelectedTunnel(selectedTunnel());
                    // If status specifically failed (which would leave everything
                    // showing "Disconnected"), show the real error once so it's
                    // diagnosable instead of hidden.
                    if (statusError != null && !statusErrorShown) {
                        statusErrorShown = true;
                        PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, statusError,
                                "Could not load tunnel status (tunnels will show as Disconnected until this is fixed):");
                    }
                } catch (Exception e) {
                    log.error("Failed to load tunnels", e);
                    latestStatuses = Map.of();
                    tableModel.setData(Collections.emptyList(), Collections.emptyMap());
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
                updateButtonStates();
            }
        }.execute();
    }

    @Override
    public boolean doSave() {
        return true;
    }

    /** Keeps the same tunnel selected across a data refresh. */
    private void reselect(SshTunnel previous) {
        if (previous == null) {
            return;
        }
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            if (tableModel.getTunnelAt(i).getId().equals(previous.getId())) {
                int view = table.convertRowIndexToView(i);
                table.getSelectionModel().setSelectionInterval(view, view);
                return;
            }
        }
    }

    private void updateButtonStates() {
        var tunnel = selectedTunnel();
        boolean selected = tunnel != null;
        btnEdit.setEnabled(selected);
        btnDuplicate.setEnabled(selected);
        btnDelete.setEnabled(selected);
        btnStart.setEnabled(selected);
        btnStop.setEnabled(selected);
        btnEnable.setEnabled(selected && !tunnel.isEnabled());
        btnDisable.setEnabled(selected && tunnel.isEnabled());
    }

    /** Flips the enabled attribute of the selected tunnel and saves it. */
    private void setEnabledState(boolean enable) {
        var selected = selectedTunnel();
        if (selected == null || selected.isEnabled() == enable) {
            return;
        }
        var updated = selected.copy();
        updated.setEnabled(enable);
        // Masked secrets resolve against the stored tunnel on the server.
        saveTunnel(updated, false);
    }

    private SshTunnel selectedTunnel() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        return tableModel.getTunnelAt(table.convertRowIndexToModel(viewRow));
    }

    private Set<String> otherNames(String excludeId) {
        var names = new HashSet<String>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            var tunnel = tableModel.getTunnelAt(i);
            if (excludeId == null || !excludeId.equals(tunnel.getId())) {
                names.add(tunnel.getName().toLowerCase());
            }
        }
        return names;
    }

    /** LOCAL forwards of all tunnels except excludeId, each tagged with its owning
     *  tunnel's name so a bind-port collision can name the conflicting tunnel. */
    private List<NamedForward> otherLocalForwards(String excludeId) {
        var result = new java.util.ArrayList<NamedForward>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            var tunnel = tableModel.getTunnelAt(i);
            if (excludeId == null || !excludeId.equals(tunnel.getId())) {
                for (var forward : tunnel.getForwards()) {
                    if (forward.getDirection() == ForwardDirection.LOCAL) {
                        result.add(new NamedForward(tunnel.getName(), forward));
                    }
                }
            }
        }
        return result;
    }

    private void newTunnel() {
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), new SshTunnel(),
                otherNames(null), otherLocalForwards(null));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), true);
        }
    }

    private void editTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), selected.copy(),
                otherNames(selected.getId()), otherLocalForwards(selected.getId()));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), false);
        }
    }

    private void duplicateTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        var copy = selected.copy();
        copy.setId(null);
        copy.setName(selected.getName() + " (copy)");
        // The source came from getTunnels(), so its secrets are the mask string.
        // Blank them so the admin re-enters real secrets for the new tunnel.
        copy.setPassword("");
        copy.setPrivateKeyPem("");
        copy.setPrivateKeyPassphrase("");
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), copy,
                otherNames(null), otherLocalForwards(null));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), true);
        }
    }

    private void saveTunnel(SshTunnel tunnel, boolean isNew) {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                if (isNew) {
                    getServlet().createTunnel(tunnel);
                } else {
                    getServlet().updateTunnel(tunnel.getId(), tunnel);
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                    burstRefresh();
                } catch (Exception e) {
                    log.error("Failed to save tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private void deleteTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        int choice = JOptionPane.showConfirmDialog(this,
                "Delete tunnel '" + selected.getName() + "'? It will be stopped immediately.",
                "Confirm Delete", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                getServlet().deleteTunnel(selected.getId());
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                } catch (Exception e) {
                    log.error("Failed to delete tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private void runControl(boolean start) {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                if (start) {
                    getServlet().startTunnel(selected.getId());
                } else {
                    getServlet().stopTunnel(selected.getId());
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                    burstRefresh();
                } catch (Exception e) {
                    log.error("Failed to control tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private SshTunnelServletInterface getServlet() {
        if (servlet == null) {
            servlet = PlatformUI.MIRTH_FRAME.mirthClient.getServlet(SshTunnelServletInterface.class);
        }
        return servlet;
    }
}
