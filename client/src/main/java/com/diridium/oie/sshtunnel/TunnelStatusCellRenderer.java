/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/** Colors the Status and Host Key cells so state reads at a glance. */
public class TunnelStatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color GREEN = new Color(0x1B, 0x7F, 0x2B);
    private static final Color AMBER = new Color(0xB8, 0x6E, 0x00);
    private static final Color RED = new Color(0xC0, 0x28, 0x28);
    private static final Color GREY = new Color(0x70, 0x70, 0x70);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
            boolean hasFocus, int row, int column) {
        var c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (isSelected) {
            return c;
        }
        var model = (TunnelTableModel) table.getModel();
        int modelRow = table.convertRowIndexToModel(row);
        int modelCol = table.convertColumnIndexToModel(column);
        if (modelCol == TunnelTableModel.COL_HOST_KEY) {
            c.setForeground(model.isVerifiedAt(modelRow) ? GREEN : AMBER);
        } else {
            c.setForeground(colorFor(model.getStateAt(modelRow)));
        }
        return c;
    }

    private static Color colorFor(TunnelState state) {
        return switch (state) {
            case CONNECTED -> GREEN;
            case CONNECTING, RECONNECTING -> AMBER;
            case FAILED -> RED;
            case DISCONNECTED, DISABLED -> GREY;
        };
    }
}
