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

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

import net.miginfocom.swing.MigLayout;

/**
 * The settings tab's bottom pane: the connection-event log for the selected
 * tunnel (or all tunnels). Live status now lives in the tunnel table's columns;
 * this pane is only the event history. Passive view — the settings panel's
 * refresh pushes data in; the pane does no network I/O.
 */
public class TunnelDiagnosticsPane extends JPanel {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final JRadioButton thisTunnelButton = new JRadioButton("This tunnel", true);
    private final JRadioButton allTunnelsButton = new JRadioButton("All tunnels");
    private final EventTableModel eventModel = new EventTableModel();

    private String selectedTunnelId;
    private Map<String, String> tunnelNames = Map.of();
    private Map<String, List<TunnelEvent>> eventsByTunnel = Map.of();

    public TunnelDiagnosticsPane() {
        super(new BorderLayout());

        var group = new ButtonGroup();
        group.add(thisTunnelButton);
        group.add(allTunnelsButton);
        thisTunnelButton.addActionListener(e -> refreshEvents());
        allTunnelsButton.addActionListener(e -> refreshEvents());

        // Tight spacing so the two options sit next to each other, not spread apart.
        var filterBar = new JPanel(new MigLayout("insets 4 8 4 8, gapx 6", "[][][]push"));
        filterBar.add(new JLabel("Event log:"));
        filterBar.add(thisTunnelButton);
        filterBar.add(allTunnelsButton);

        var table = new JTable(eventModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(130);
        table.getColumnModel().getColumn(2).setPreferredWidth(50);
        table.getColumnModel().getColumn(3).setPreferredWidth(380);

        add(filterBar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    /** Tracks which tunnel the "This tunnel" filter shows. */
    public void setSelectedTunnel(SshTunnel tunnel) {
        selectedTunnelId = tunnel != null ? tunnel.getId() : null;
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
        rows.sort(Comparator.comparingLong((EventRow r) -> r.event.getTimestamp()).reversed());
        eventModel.setRows(rows);
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
