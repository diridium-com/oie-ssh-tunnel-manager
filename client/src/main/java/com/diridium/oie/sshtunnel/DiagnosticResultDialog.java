/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import net.miginfocom.swing.MigLayout;

/**
 * Shows the per-step result of a connection diagnostic: each stage, its outcome,
 * detail, and duration, with a colored status column.
 */
public class DiagnosticResultDialog extends JDialog {

    public DiagnosticResultDialog(Window parent, DiagnosticResult result) {
        super(parent, "Connection Test", ModalityType.APPLICATION_MODAL);

        var summary = new JLabel(result.getSummary());
        summary.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 12, 6, 12));

        var table = new JTable(new StepTableModel(result));
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setCellRenderer(new StatusCellRenderer());
        table.getColumnModel().getColumn(2).setPreferredWidth(360);
        table.getColumnModel().getColumn(3).setPreferredWidth(60);

        var close = new JButton("Close");
        close.addActionListener(e -> dispose());
        var buttons = new JPanel(new MigLayout("insets 8", "push[]"));
        buttons.add(close);

        setLayout(new BorderLayout());
        add(summary, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
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

        setSize(new Dimension(680, 340));
        setLocationRelativeTo(parent);
    }

    private static class StepTableModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Step", "Result", "Detail", "ms"};
        private final transient DiagnosticResult result;

        StepTableModel(DiagnosticResult result) {
            this.result = result;
        }

        DiagnosticStep stepAt(int row) {
            return result.getSteps().get(row);
        }

        @Override
        public int getRowCount() {
            return result.getSteps().size();
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
            var step = result.getSteps().get(row);
            return switch (column) {
                case 0 -> step.getName();
                case 1 -> step.getStatus().toString();
                case 2 -> step.getDetail();
                case 3 -> step.getDurationMs() > 0 ? String.valueOf(step.getDurationMs()) : "";
                default -> "";
            };
        }
    }

    /** Colors the result column by status so pass/warn/fail/skip read at a glance. */
    private static class StatusCellRenderer extends DefaultTableCellRenderer {

        private static final Color GREEN = new Color(0x1B, 0x7F, 0x2B);
        private static final Color AMBER = new Color(0xB8, 0x6E, 0x00);
        private static final Color RED = new Color(0xC0, 0x28, 0x28);
        private static final Color GREY = new Color(0x70, 0x70, 0x70);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            var c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected) {
                var model = (StepTableModel) table.getModel();
                c.setForeground(switch (model.stepAt(row).getStatus()) {
                    case PASS -> GREEN;
                    case WARN -> AMBER;
                    case FAIL -> RED;
                    case SKIP -> GREY;
                });
            }
            return c;
        }
    }
}
