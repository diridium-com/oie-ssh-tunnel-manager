/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import net.miginfocom.swing.MigLayout;

/**
 * Modal view of a connection test. Opens immediately showing the real results
 * layout with a spinner in the top bar, so a multi-second SSH probe doesn't look
 * like a hung, broken button, then fills in the body when results arrive.
 * Results can't render into the settings tab behind the modal edit dialog, which
 * is why this is a separate dialog.
 */
public class DiagnosticResultDialog extends JDialog {

    private final DiagnosticResultPanel panel = new DiagnosticResultPanel();

    public DiagnosticResultDialog(Window parent) {
        super(parent, "Connection Test", ModalityType.APPLICATION_MODAL);

        panel.showRunning();

        var close = new JButton("Close");
        close.addActionListener(e -> dispose());
        var buttons = new JPanel(new MigLayout("insets 8", "push[]"));
        buttons.add(close);

        setLayout(new BorderLayout());
        add(panel, BorderLayout.CENTER);
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

        setSize(new Dimension(700, 460));
        setLocationRelativeTo(parent);
    }

    /** Fills in the finished results (the one-time refresh). */
    public void showResult(DiagnosticResult result) {
        panel.setResult(result);
    }

    /** Shows a message when the test call itself failed to run. */
    public void showError(String message) {
        panel.showError(message);
    }
}
