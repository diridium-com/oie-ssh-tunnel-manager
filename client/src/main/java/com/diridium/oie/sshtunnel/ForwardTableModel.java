/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

/** Editable table model for a tunnel's port forwards. */
public class ForwardTableModel extends AbstractTableModel {

    private static final String[] COLUMNS =
            {"Direction", "Bind Host", "Bind Port", "Destination Host", "Destination Port"};

    private final List<PortForward> forwards = new ArrayList<>();

    public void setForwards(List<PortForward> source) {
        forwards.clear();
        if (source != null) {
            for (var forward : source) {
                forwards.add(forward.copy());
            }
        }
        fireTableDataChanged();
    }

    public List<PortForward> getForwards() {
        var copy = new ArrayList<PortForward>(forwards.size());
        for (var forward : forwards) {
            copy.add(forward.copy());
        }
        return copy;
    }

    public void addForward() {
        forwards.add(new PortForward(ForwardDirection.LOCAL, "127.0.0.1", 0, "", 0));
        int row = forwards.size() - 1;
        fireTableRowsInserted(row, row);
    }

    public void removeForward(int row) {
        if (row >= 0 && row < forwards.size()) {
            forwards.remove(row);
            fireTableRowsDeleted(row, row);
        }
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
    public Class<?> getColumnClass(int column) {
        return column == 0 ? ForwardDirection.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return true;
    }

    @Override
    public Object getValueAt(int row, int column) {
        var forward = forwards.get(row);
        return switch (column) {
            case 0 -> forward.getDirection();
            case 1 -> forward.getBindHost();
            case 2 -> forward.getBindPort() == 0 ? "" : String.valueOf(forward.getBindPort());
            case 3 -> forward.getDestinationHost();
            case 4 -> forward.getDestinationPort() == 0 ? "" : String.valueOf(forward.getDestinationPort());
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        var forward = forwards.get(row);
        switch (column) {
            case 0 -> forward.setDirection((ForwardDirection) value);
            case 1 -> forward.setBindHost(value != null ? value.toString().trim() : "");
            case 2 -> forward.setBindPort(parsePort(value));
            case 3 -> forward.setDestinationHost(value != null ? value.toString().trim() : "");
            case 4 -> forward.setDestinationPort(parsePort(value));
            default -> { }
        }
        fireTableCellUpdated(row, column);
    }

    private static int parsePort(Object value) {
        if (value == null) {
            return 0;
        }
        try {
            var text = value.toString().trim();
            return text.isEmpty() ? 0 : Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
