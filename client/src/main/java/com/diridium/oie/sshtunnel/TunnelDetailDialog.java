/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;

import net.miginfocom.swing.MigLayout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Read-only diagnostics view for one tunnel: live status (state, uptime, failed
 * attempts, next-retry countdown, last error), its forwards, and the rolling
 * connection-event log. Refresh re-pulls status and events from the server.
 */
public class TunnelDetailDialog extends JDialog {

    private static final Logger log = LoggerFactory.getLogger(TunnelDetailDialog.class);
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final transient SshTunnelServletInterface servlet;
    private final transient SshTunnel tunnel;

    private final JLabel stateValue = new JLabel();
    private final JLabel endpointValue = new JLabel();
    private final JLabel uptimeValue = new JLabel();
    private final JLabel attemptsValue = new JLabel();
    private final JLabel retryValue = new JLabel();
    private final JLabel errorValue = new JLabel();
    private final EventTableModel eventModel = new EventTableModel();

    public TunnelDetailDialog(Window parent, SshTunnelServletInterface servlet, SshTunnel tunnel,
            SshTunnelStatus status) {
        super(parent, "Tunnel: " + tunnel.getName(), ModalityType.APPLICATION_MODAL);
        this.servlet = servlet;
        this.tunnel = tunnel;

        var tabs = new JTabbedPane();
        tabs.addTab("Status", buildStatusTab());
        tabs.addTab("Forwards", buildForwardsTab());
        tabs.addTab("Event Log", buildEventTab());

        var refresh = new JButton("Refresh");
        refresh.addActionListener(e -> reload());
        var close = new JButton("Close");
        close.addActionListener(e -> dispose());
        var buttons = new JPanel(new MigLayout("insets 8", "push[][]"));
        buttons.add(refresh);
        buttons.add(close);

        setLayout(new BorderLayout());
        add(tabs, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        getRootPane().setDefaultButton(close);
        var escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "close");
        getRootPane().getActionMap().put("close", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose();
            }
        });

        applyStatus(status);
        loadEvents();

        setSize(new Dimension(620, 460));
        setLocationRelativeTo(parent);
    }

    private JPanel buildStatusTab() {
        var panel = new JPanel(new MigLayout("insets 12, wrap 2", "[right][grow,fill]"));
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
        panel.add(new JLabel("Last error:"));
        panel.add(errorValue);
        return panel;
    }

    private JPanel buildForwardsTab() {
        var panel = new JPanel(new BorderLayout());
        var table = new JTable(new ForwardsViewModel(tunnel.getForwards()));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildEventTab() {
        var panel = new JPanel(new BorderLayout());
        var table = new JTable(eventModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);
        table.getColumnModel().getColumn(2).setPreferredWidth(380);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private void reload() {
        new SwingWorker<SshTunnelStatus, Void>() {
            private List<TunnelEvent> events = List.of();

            @Override
            protected SshTunnelStatus doInBackground() throws Exception {
                SshTunnelStatus found = null;
                for (var status : servlet.getStatuses()) {
                    if (status.getTunnelId().equals(tunnel.getId())) {
                        found = status;
                        break;
                    }
                }
                events = servlet.getTunnelEvents(tunnel.getId());
                return found;
            }

            @Override
            protected void done() {
                try {
                    applyStatus(get());
                    eventModel.setEvents(events);
                } catch (Exception e) {
                    log.error("Failed to refresh tunnel detail", e);
                }
            }
        }.execute();
    }

    private void loadEvents() {
        new SwingWorker<List<TunnelEvent>, Void>() {
            @Override
            protected List<TunnelEvent> doInBackground() throws Exception {
                return servlet.getTunnelEvents(tunnel.getId());
            }

            @Override
            protected void done() {
                try {
                    eventModel.setEvents(get());
                } catch (Exception e) {
                    log.debug("Could not load tunnel events", e);
                }
            }
        }.execute();
    }

    private void applyStatus(SshTunnelStatus status) {
        endpointValue.setText(tunnel.getEndpointDescription());
        if (status == null) {
            stateValue.setText(tunnel.isEnabled() ? TunnelState.DISCONNECTED.toString()
                    : TunnelState.DISABLED.toString());
            uptimeValue.setText("-");
            attemptsValue.setText("0");
            retryValue.setText("-");
            errorValue.setText("-");
            return;
        }
        var now = System.currentTimeMillis();
        stateValue.setText(status.getState().toString());
        uptimeValue.setText(status.getConnectedSince() > 0
                ? humanizeDuration(now - status.getConnectedSince()) : "-");
        attemptsValue.setText(String.valueOf(status.getFailedAttempts()));
        if (status.getNextRetryAt() > now) {
            retryValue.setText("in " + humanizeDuration(status.getNextRetryAt() - now));
        } else {
            retryValue.setText("-");
        }
        errorValue.setText(status.getLastError() == null || status.getLastError().isEmpty()
                ? "-" : status.getLastError());
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

    private static class ForwardsViewModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Direction", "Bind", "Destination"};
        private final transient List<PortForward> forwards;

        ForwardsViewModel(List<PortForward> forwards) {
            this.forwards = forwards != null ? forwards : new ArrayList<>();
        }

        @Override
        public int getRowCount() {
            return forwards.size();
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
            var forward = forwards.get(row);
            return switch (column) {
                case 0 -> forward.getDirection().toString();
                case 1 -> forward.getBindHost() + ":" + forward.getBindPort();
                case 2 -> forward.getDestinationHost() + ":" + forward.getDestinationPort();
                default -> "";
            };
        }
    }

    private static class EventTableModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Time", "Level", "Message"};
        private List<TunnelEvent> events = new ArrayList<>();

        void setEvents(List<TunnelEvent> events) {
            // Newest first.
            var copy = new ArrayList<>(events != null ? events : List.<TunnelEvent>of());
            java.util.Collections.reverse(copy);
            this.events = copy;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return events.size();
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
            var event = events.get(row);
            return switch (column) {
                case 0 -> TIME_FMT.format(Instant.ofEpochMilli(event.getTimestamp()));
                case 1 -> event.getLevel().toString();
                case 2 -> event.getMessage();
                default -> "";
            };
        }
    }
}
