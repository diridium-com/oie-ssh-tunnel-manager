/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.table.AbstractTableModel;

/** Table model for the tunnel list, joining each tunnel with its runtime status. */
public class TunnelTableModel extends AbstractTableModel {

    static final int COL_HOST_KEY = 4;
    static final int COL_STATUS = 5;

    private static final String[] COLUMNS = {"Name", "Endpoint", "Forwards", "Enabled", "Host Key",
            "Status", "Uptime", "Attempts", "Next Retry", "Last Error"};

    private List<SshTunnel> tunnels = new ArrayList<>();
    private Map<String, SshTunnelStatus> statuses = Map.of();

    public void setData(List<SshTunnel> tunnels, Map<String, SshTunnelStatus> statuses) {
        this.tunnels = tunnels != null ? tunnels : new ArrayList<>();
        this.statuses = statuses != null ? statuses : Map.of();
        fireTableDataChanged();
    }

    /**
     * Refreshes the data. If the same tunnels are present (same ids in order) it
     * fires only row updates, which preserves the current selection — important
     * for a live poll, since a full fireTableDataChanged would clear the
     * selection and break Edit/Delete/etc. Returns true if it rebuilt the table
     * (structure changed and the selection was reset).
     */
    public boolean refreshData(List<SshTunnel> tunnels, Map<String, SshTunnelStatus> statuses) {
        var newTunnels = tunnels != null ? tunnels : new ArrayList<SshTunnel>();
        var sameStructure = sameIds(this.tunnels, newTunnels);
        this.tunnels = newTunnels;
        this.statuses = statuses != null ? statuses : Map.of();
        if (sameStructure) {
            if (!newTunnels.isEmpty()) {
                fireTableRowsUpdated(0, newTunnels.size() - 1);
            }
            return false;
        }
        fireTableDataChanged();
        return true;
    }

    private static boolean sameIds(List<SshTunnel> a, List<SshTunnel> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!a.get(i).getId().equals(b.get(i).getId())) {
                return false;
            }
        }
        return true;
    }

    public SshTunnel getTunnelAt(int row) {
        return tunnels.get(row);
    }

    /** Runtime state for the row, for the status cell renderer. */
    public TunnelState getStateAt(int row) {
        var tunnel = tunnels.get(row);
        var status = statuses.get(tunnel.getId());
        if (status != null) {
            return status.getState();
        }
        return tunnel.isEnabled() ? TunnelState.DISCONNECTED : TunnelState.DISABLED;
    }

    public boolean isVerifiedAt(int row) {
        return tunnels.get(row).isVerifyHostKey();
    }

    @Override
    public int getRowCount() {
        return tunnels.size();
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
        var tunnel = tunnels.get(row);
        var status = statuses.get(tunnel.getId());
        return switch (column) {
            case 0 -> tunnel.getName();
            case 1 -> tunnel.getEndpointDescription();
            case 2 -> forwardSummary(tunnel);
            case 3 -> tunnel.isEnabled() ? "Yes" : "No";
            case 4 -> tunnel.isVerifyHostKey() ? "Pinned" : "Unverified";
            case COL_STATUS -> statusText(tunnel, status);
            case 6 -> uptimeText(status);
            case 7 -> attemptsText(status);
            case 8 -> nextRetryText(status);
            case 9 -> status != null && status.getLastError() != null ? status.getLastError() : "";
            default -> "";
        };
    }

    /** Forwards broken out by direction, e.g. "2L / 1R" (local -L, remote -R). */
    private static String forwardSummary(SshTunnel tunnel) {
        int local = 0;
        int remote = 0;
        for (var forward : tunnel.getForwards()) {
            if (forward.getDirection() == ForwardDirection.REMOTE) {
                remote++;
            } else {
                local++;
            }
        }
        return local + "L / " + remote + "R";
    }

    private String statusText(SshTunnel tunnel, SshTunnelStatus status) {
        if (status == null) {
            return tunnel.isEnabled() ? TunnelState.DISCONNECTED.toString() : TunnelState.DISABLED.toString();
        }
        return status.getState().toString();
    }

    private static String uptimeText(SshTunnelStatus status) {
        if (status == null || status.getState() != TunnelState.CONNECTED || status.getConnectedSince() <= 0) {
            return "";
        }
        return humanizeDuration(System.currentTimeMillis() - status.getConnectedSince());
    }

    private static String attemptsText(SshTunnelStatus status) {
        if (status == null || status.getFailedAttempts() <= 0) {
            return "";
        }
        return String.valueOf(status.getFailedAttempts());
    }

    private static String nextRetryText(SshTunnelStatus status) {
        if (status == null || status.getNextRetryAt() <= 0) {
            return "";
        }
        long delta = status.getNextRetryAt() - System.currentTimeMillis();
        return delta <= 0 ? "now" : "in " + humanizeDuration(delta);
    }

    static String humanizeDuration(long millis) {
        long seconds = Math.max(0, millis / 1000);
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        if (h > 0) {
            return h + "h " + m + "m";
        }
        if (m > 0) {
            return m + "m " + s + "s";
        }
        return s + "s";
    }
}
