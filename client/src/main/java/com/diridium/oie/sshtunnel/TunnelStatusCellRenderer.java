/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Colors only what needs attention: a Failed tunnel is red so it stands out in a
 * list, and an Unverified host key is amber as a standing warning. Everything
 * else (including Connected, Disabled, and a pinned host key) is plain text —
 * the normal cases don't need a color, and coloring them just adds noise.
 */
public class TunnelStatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color RED = new Color(0xC0, 0x28, 0x28);
    private static final Color AMBER = new Color(0xB8, 0x6E, 0x00);

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
            c.setForeground(model.isVerifiedAt(modelRow) ? table.getForeground() : AMBER);
        } else if (modelCol == TunnelTableModel.COL_STATUS) {
            c.setForeground(model.getStateAt(modelRow) == TunnelState.FAILED ? RED : table.getForeground());
        }
        return c;
    }
}
