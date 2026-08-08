/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.table.AbstractTableModel;

/** Table model for the tunnel list, joining each tunnel with its runtime status. */
public class TunnelTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"Name", "Endpoint", "Forwards", "Enabled", "Status"};

    private List<SshTunnel> tunnels = new ArrayList<>();
    private Map<String, SshTunnelStatus> statuses = Map.of();

    public void setData(List<SshTunnel> tunnels, Map<String, SshTunnelStatus> statuses) {
        this.tunnels = tunnels != null ? tunnels : new ArrayList<>();
        this.statuses = statuses != null ? statuses : Map.of();
        fireTableDataChanged();
    }

    public SshTunnel getTunnelAt(int row) {
        return tunnels.get(row);
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
        return switch (column) {
            case 0 -> tunnel.getName();
            case 1 -> tunnel.getEndpointDescription();
            case 2 -> tunnel.getForwards().size();
            case 3 -> tunnel.isEnabled() ? "Yes" : "No";
            case 4 -> statusText(tunnel);
            default -> "";
        };
    }

    private String statusText(SshTunnel tunnel) {
        var status = statuses.get(tunnel.getId());
        if (status == null) {
            return tunnel.isEnabled() ? TunnelState.DISCONNECTED.toString() : TunnelState.DISABLED.toString();
        }
        var text = status.getState().toString();
        if ((status.getState() == TunnelState.FAILED || status.getState() == TunnelState.RECONNECTING)
                && status.getLastError() != null && !status.getLastError().isEmpty()) {
            text += " - " + status.getLastError();
        }
        return text;
    }
}
