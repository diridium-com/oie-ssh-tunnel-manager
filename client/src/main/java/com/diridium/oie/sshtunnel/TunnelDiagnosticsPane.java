/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

import net.miginfocom.swing.MigLayout;

/**
 * The settings tab's bottom pane: live status and event log for the selected
 * tunnel (or all tunnels), plus the last Test Connection result. Passive view —
 * the settings panel's poll pushes data in; the pane does no network I/O.
 */
public class TunnelDiagnosticsPane extends JPanel {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final JLabel stateValue = new JLabel("-");
    private final JLabel endpointValue = new JLabel("-");
    private final JLabel uptimeValue = new JLabel("-");
    private final JLabel attemptsValue = new JLabel("-");
    private final JLabel retryValue = new JLabel("-");
    private final JLabel errorValue = new JLabel("-");
    private final JLabel hostKeyValue = new JLabel("-");

    private final JRadioButton thisTunnelButton = new JRadioButton("This tunnel", true);
    private final JRadioButton allTunnelsButton = new JRadioButton("All tunnels");
    private final EventTableModel eventModel = new EventTableModel();
    private final JTabbedPane tabs = new JTabbedPane();

    private String selectedTunnelId;
    private Map<String, String> tunnelNames = Map.of();
    private Map<String, List<TunnelEvent>> eventsByTunnel = Map.of();

    public TunnelDiagnosticsPane() {
        super(new BorderLayout());
        tabs.addTab("Status", buildStatusTab());
        tabs.addTab("Event Log", buildEventTab());
        add(tabs, BorderLayout.CENTER);
    }

    private JPanel buildStatusTab() {
        var panel = new JPanel(new MigLayout("insets 10, wrap 4", "[right][grow,fill]20[right][grow,fill]"));
        panel.add(new JLabel("State:"));
        panel.add(stateValue);
        panel.add(new JLabel("Endpoint:"));
        panel.add(endpointValue);
        panel.add(new JLabel("Uptime:"));
        panel.add(uptimeValue);
        panel.add(new JLabel("Failed attempts:"));
        panel.add(attemptsValue);
        panel.add(new JLabel("Next retry:"));
        panel.add(retryValue);
        panel.add(new JLabel("Host key:"));
        panel.add(hostKeyValue);
        panel.add(new JLabel("Last error:"));
        panel.add(errorValue, "span 3");
        return panel;
    }

    private JPanel buildEventTab() {
        var panel = new JPanel(new BorderLayout());

        var group = new ButtonGroup();
        group.add(thisTunnelButton);
        group.add(allTunnelsButton);
        thisTunnelButton.addActionListener(e -> refreshEvents());
        allTunnelsButton.addActionListener(e -> refreshEvents());

        var filterBar = new JPanel(new MigLayout("insets 4 8 4 8", "[][]push"));
        filterBar.add(new JLabel("Show:"));
        filterBar.add(thisTunnelButton);
        filterBar.add(allTunnelsButton);

        var table = new JTable(eventModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(130);
        table.getColumnModel().getColumn(2).setPreferredWidth(50);
        table.getColumnModel().getColumn(3).setPreferredWidth(360);

        panel.add(filterBar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    /** Updates the status tab for the selected tunnel (null clears it). */
    public void setSelection(SshTunnel tunnel, SshTunnelStatus status) {
        selectedTunnelId = tunnel != null ? tunnel.getId() : null;
        if (tunnel == null) {
            stateValue.setText("-");
            endpointValue.setText("-");
            uptimeValue.setText("-");
            attemptsValue.setText("-");
            retryValue.setText("-");
            errorValue.setText("-");
            hostKeyValue.setText("-");
            refreshEvents();
            return;
        }
        endpointValue.setText(tunnel.getEndpointDescription());
        hostKeyValue.setText(tunnel.isVerifyHostKey()
                ? (tunnel.getAcceptedHostKey() == null || tunnel.getAcceptedHostKey().isEmpty()
                        ? "verification on, no key accepted" : "pinned (" + tunnel.getAcceptedHostKeyType() + ")")
                : "NOT VERIFIED");
        var now = System.currentTimeMillis();
        if (status == null) {
            stateValue.setText(tunnel.isEnabled() ? TunnelState.DISCONNECTED.toString()
                    : TunnelState.DISABLED.toString());
            uptimeValue.setText("-");
            attemptsValue.setText("0");
            retryValue.setText("-");
            errorValue.setText("-");
        } else {
            stateValue.setText(status.getState().toString());
            uptimeValue.setText(status.getConnectedSince() > 0
                    ? humanizeDuration(now - status.getConnectedSince()) : "-");
            attemptsValue.setText(String.valueOf(status.getFailedAttempts()));
            retryValue.setText(status.getNextRetryAt() > now
                    ? "in " + humanizeDuration(status.getNextRetryAt() - now) : "-");
            errorValue.setText(status.getLastError() == null || status.getLastError().isEmpty()
                    ? "-" : status.getLastError());
        }
        refreshEvents();
    }

    /** Pushes the latest event data for all tunnels; the pane renders per the filter. */
    public void setEventData(Map<String, String> tunnelNames, Map<String, List<TunnelEvent>> eventsByTunnel) {
        this.tunnelNames = tunnelNames != null ? tunnelNames : Map.of();
        this.eventsByTunnel = eventsByTunnel != null ? eventsByTunnel : Map.of();
        refreshEvents();
    }

    /** Whether the event log is currently showing all tunnels (so the poll fetches them all). */
    public boolean isShowingAllTunnels() {
        return allTunnelsButton.isSelected();
    }

    private void refreshEvents() {
        var rows = new ArrayList<EventRow>();
        if (allTunnelsButton.isSelected()) {
            for (var entry : eventsByTunnel.entrySet()) {
                var name = tunnelNames.getOrDefault(entry.getKey(), entry.getKey());
                for (var event : entry.getValue()) {
                    rows.add(new EventRow(name, event));
                }
            }
        } else if (selectedTunnelId != null) {
            var name = tunnelNames.getOrDefault(selectedTunnelId, "");
            for (var event : eventsByTunnel.getOrDefault(selectedTunnelId, List.of())) {
                rows.add(new EventRow(name, event));
            }
        }
        // Newest first.
        rows.sort(Comparator.comparingLong((EventRow r) -> r.event.getTimestamp()).reversed());
        eventModel.setRows(rows);
    }

    static String humanizeDuration(long millis) {
        long seconds = Math.max(0, millis / 1000);
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        if (h > 0) {
            return h + "h " + m + "m " + s + "s";
        }
        if (m > 0) {
            return m + "m " + s + "s";
        }
        return s + "s";
    }

    private record EventRow(String tunnelName, TunnelEvent event) {
    }

    private static class EventTableModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Time", "Tunnel", "Level", "Message"};
        private List<EventRow> rows = new ArrayList<>();

        void setRows(List<EventRow> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            var r = rows.get(row);
            return switch (column) {
                case 0 -> TIME_FMT.format(Instant.ofEpochMilli(r.event.getTimestamp()));
                case 1 -> r.tunnelName;
                case 2 -> r.event.getLevel().toString();
                case 3 -> r.event.getMessage();
                default -> "";
            };
        }
    }
}
