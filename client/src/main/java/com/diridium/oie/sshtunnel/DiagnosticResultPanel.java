/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import net.miginfocom.swing.MigLayout;

/**
 * Reusable view of a {@link DiagnosticResult}: a colored per-step table on top
 * and, below, the selected step's detail plus any actionable hint with a Copy
 * button. Used both in the edit dialog's Test Connection and in the settings
 * tab's diagnostics pane.
 */
public class DiagnosticResultPanel extends JPanel {

    private final JLabel summary = new JLabel(" ");
    private final JProgressBar progress = new JProgressBar();
    private final StepTableModel model = new StepTableModel();
    private final JTable table = new JTable(model);
    private final JTextArea detailArea = new JTextArea(4, 40);
    private final JButton copyButton = new JButton("Copy");

    public DiagnosticResultPanel() {
        super(new BorderLayout());

        summary.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        progress.setIndeterminate(true);
        progress.setVisible(false);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setCellRenderer(new StatusCellRenderer(model));
        table.getColumnModel().getColumn(2).setPreferredWidth(360);
        table.getColumnModel().getColumn(3).setPreferredWidth(50);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });

        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        copyButton.setEnabled(false);
        copyButton.addActionListener(e -> copyDetail());

        var detailPanel = new JPanel(new MigLayout("insets 6, fill", "[grow][]", "[grow][]"));
        detailPanel.add(new JScrollPane(detailArea), "grow, span 2, wrap");
        detailPanel.add(new JLabel(""), "growx");
        detailPanel.add(copyButton);

        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailPanel);
        split.setResizeWeight(0.62);
        split.setBorder(null);

        var north = new JPanel(new BorderLayout());
        north.add(summary, BorderLayout.CENTER);
        var progressHolder = new JPanel(new MigLayout("insets 6 6 6 10, center"));
        progressHolder.add(progress, "w 140!, h 14!");
        north.add(progressHolder, BorderLayout.EAST);

        add(north, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setResult(DiagnosticResult result) {
        progress.setVisible(false);
        model.setResult(result);
        summary.setText((result.isSuccess() ? "✓ " : "✗ ") + result.getSummary());
        // Auto-select the first step that carries a hint (usually the failure),
        // else the first failed/warn step, else the first row.
        int target = firstRowWithHint();
        if (target < 0) {
            target = firstProblemRow();
        }
        if (target < 0 && model.getRowCount() > 0) {
            target = 0;
        }
        if (target >= 0) {
            table.getSelectionModel().setSelectionInterval(target, target);
        } else {
            detailArea.setText("");
            copyButton.setEnabled(false);
        }
    }

    /** Running state: spinner in the top bar, empty table below, ready to fill in. */
    public void showRunning() {
        model.setResult(new DiagnosticResult());
        summary.setText("Running connection test…");
        detailArea.setText("");
        copyButton.setEnabled(false);
        progress.setVisible(true);
    }

    /** Shows a message when the test call itself failed to run (not a diagnostic step). */
    public void showError(String message) {
        progress.setVisible(false);
        model.setResult(new DiagnosticResult());
        summary.setText("✗ The connection test could not run.");
        detailArea.setText(message != null ? message : "");
        detailArea.setCaretPosition(0);
        copyButton.setEnabled(false);
    }

    private int firstRowWithHint() {
        for (int i = 0; i < model.getRowCount(); i++) {
            if (!model.stepAt(i).getHint().isEmpty()) {
                return i;
            }
        }
        return -1;
    }

    private int firstProblemRow() {
        for (int i = 0; i < model.getRowCount(); i++) {
            var s = model.stepAt(i).getStatus();
            if (s == StepStatus.FAIL || s == StepStatus.WARN) {
                return i;
            }
        }
        return -1;
    }

    private void showSelectedDetail() {
        int row = table.getSelectedRow();
        if (row < 0) {
            detailArea.setText("");
            copyButton.setEnabled(false);
            return;
        }
        var step = model.stepAt(row);
        var text = new StringBuilder(step.getName());
        if (!step.getDetail().isEmpty()) {
            text.append("\n\n").append(step.getDetail());
        }
        if (!step.getHint().isEmpty()) {
            text.append("\n\n").append(step.getHint());
        }
        detailArea.setText(text.toString());
        detailArea.setCaretPosition(0);
        copyButton.setEnabled(!step.getHint().isEmpty() || !step.getDetail().isEmpty());
    }

    private void copyDetail() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        var step = model.stepAt(row);
        // Prefer copying the hint (often an authorized_keys line); fall back to detail.
        var text = !step.getHint().isEmpty() ? step.getHint() : step.getDetail();
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private static class StepTableModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Step", "Result", "Detail", "ms"};
        private transient DiagnosticResult result = new DiagnosticResult();

        void setResult(DiagnosticResult result) {
            this.result = result;
            fireTableDataChanged();
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

    private static class StatusCellRenderer extends DefaultTableCellRenderer {

        static final Color GREEN = new Color(0x1B, 0x7F, 0x2B);
        static final Color AMBER = new Color(0xB8, 0x6E, 0x00);
        static final Color RED = new Color(0xC0, 0x28, 0x28);
        static final Color GREY = new Color(0x70, 0x70, 0x70);

        private final transient StepTableModel model;

        StatusCellRenderer(StepTableModel model) {
            this.model = model;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            var c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected) {
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
