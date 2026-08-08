/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingWorker;

import com.mirth.connect.client.ui.PlatformUI;

import net.miginfocom.swing.MigLayout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Create/edit dialog for one SSH tunnel: endpoint, authentication, host-key
 * acceptance, port forwards, and a live connection test. Extends JDialog with
 * an escape-to-cancel binding, per house convention.
 */
public class SshTunnelDialog extends JDialog {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelDialog.class);

    private final transient SshTunnelServletInterface servlet;
    private final transient SshTunnel tunnel;
    private final transient java.util.Set<String> existingNames;
    private boolean saved;

    private JTextField nameField;
    private JCheckBox enabledCheck;
    private JTextField hostField;
    private JSpinner portSpinner;
    private JTextField usernameField;

    private JComboBox<AuthMethod> authCombo;
    private JPasswordField passwordField;
    private JComboBox<KeySource> keySourceCombo;
    private JTextField keyPathField;
    private JTextArea keyPemArea;
    private JPasswordField passphraseField;
    private JPanel passwordPanel;
    private JPanel keyPanel;
    private JPanel keyPathPanel;
    private JPanel keyPemPanel;

    private JCheckBox verifyHostKeyCheck;
    private JLabel hostKeyLabel;
    private JButton fetchHostKeyButton;

    private JSpinner keepAliveSpinner;
    private JSpinner keepAliveCountSpinner;

    private ForwardTableModel forwardModel;
    private JTable forwardTable;
    private JButton testButton;

    public SshTunnelDialog(Frame parent, SshTunnelServletInterface servlet, SshTunnel tunnel,
            java.util.Set<String> existingNames) {
        super(parent, tunnel.getId() == null ? "New SSH Tunnel" : "Edit SSH Tunnel", true);
        this.servlet = servlet;
        this.tunnel = tunnel;
        this.existingNames = existingNames != null ? existingNames : java.util.Set.of();
        buildUi();
        loadFromTunnel();
        updateAuthVisibility();
        updateHostKeyState();
        setSize(new Dimension(680, 620));
        setLocationRelativeTo(parent);
    }

    public boolean isSaved() {
        return saved;
    }

    public SshTunnel getTunnel() {
        return tunnel;
    }

    private void buildUi() {
        var tabs = new JTabbedPane();
        tabs.addTab("Connection", buildConnectionTab());
        tabs.addTab("Forwards", buildForwardsTab());

        var buttons = new JPanel(new MigLayout("insets 8", "push[][]"));
        testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> testConnection());
        var saveButton = new JButton("Save");
        saveButton.addActionListener(e -> onSave());
        var cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> onCancel());
        buttons.add(testButton);
        buttons.add(saveButton);
        buttons.add(cancelButton);

        setLayout(new BorderLayout());
        add(tabs, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        var root = getRootPane();
        root.setDefaultButton(saveButton);
        var escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "cancel");
        root.getActionMap().put("cancel", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        });
    }

    private JPanel buildConnectionTab() {
        var panel = new JPanel(new MigLayout("insets 12, wrap 2", "[right][grow,fill]"));

        nameField = new JTextField();
        enabledCheck = new JCheckBox("Enabled");
        hostField = new JTextField();
        portSpinner = new JSpinner(new SpinnerNumberModel(22, 1, 65535, 1));
        usernameField = new JTextField();

        panel.add(new JLabel("Name:"));
        panel.add(nameField);
        panel.add(new JLabel(""));
        panel.add(enabledCheck);
        panel.add(new JLabel("SSH Host:"));
        panel.add(hostField);
        panel.add(new JLabel("SSH Port:"));
        panel.add(portSpinner, "w 100!");
        panel.add(new JLabel("Username:"));
        panel.add(usernameField);

        authCombo = new JComboBox<>(AuthMethod.values());
        authCombo.addActionListener(e -> updateAuthVisibility());
        panel.add(new JLabel("Authentication:"));
        panel.add(authCombo, "w 200!");

        passwordField = new JPasswordField();
        passwordPanel = new JPanel(new MigLayout("insets 0", "[grow,fill]"));
        passwordPanel.add(passwordField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordPanel);

        keySourceCombo = new JComboBox<>(KeySource.values());
        keySourceCombo.addActionListener(e -> updateAuthVisibility());
        keyPathField = new JTextField();
        keyPemArea = new JTextArea(6, 40);
        keyPemArea.setLineWrap(false);
        passphraseField = new JPasswordField();

        keyPathPanel = new JPanel(new MigLayout("insets 0", "[grow,fill]"));
        keyPathPanel.add(keyPathField);
        keyPemPanel = new JPanel(new MigLayout("insets 0", "[grow,fill]"));
        keyPemPanel.add(new JScrollPane(keyPemArea), "grow");

        keyPanel = new JPanel(new MigLayout("insets 0, wrap 2, hidemode 3", "[right][grow,fill]"));
        keyPanel.add(new JLabel("Key Source:"));
        keyPanel.add(keySourceCombo, "w 200!");
        keyPanel.add(new JLabel("Key File Path:"));
        keyPanel.add(keyPathPanel);
        keyPanel.add(new JLabel("Private Key:"));
        keyPanel.add(keyPemPanel, "grow");
        keyPanel.add(new JLabel("Passphrase:"));
        keyPanel.add(passphraseField);
        panel.add(new JLabel(""));
        panel.add(keyPanel, "grow");

        verifyHostKeyCheck = new JCheckBox("Verify host key (recommended)");
        verifyHostKeyCheck.addActionListener(e -> updateHostKeyState());
        panel.add(new JLabel("Host Key:"));
        panel.add(verifyHostKeyCheck);

        hostKeyLabel = new JLabel("No host key accepted");
        fetchHostKeyButton = new JButton("Fetch Host Key...");
        fetchHostKeyButton.addActionListener(e -> fetchHostKey());
        var hostKeyPanel = new JPanel(new MigLayout("insets 0", "[grow,fill][]"));
        hostKeyPanel.add(hostKeyLabel);
        hostKeyPanel.add(fetchHostKeyButton);
        panel.add(new JLabel(""));
        panel.add(hostKeyPanel, "grow");

        keepAliveSpinner = new JSpinner(new SpinnerNumberModel(30, 0, 3600, 5));
        keepAliveCountSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 20, 1));
        panel.add(new JLabel("Keep-alive (sec):"));
        panel.add(keepAliveSpinner, "w 100!");
        panel.add(new JLabel("Keep-alive retries:"));
        panel.add(keepAliveCountSpinner, "w 100!");

        return panel;
    }

    private JPanel buildForwardsTab() {
        var panel = new JPanel(new BorderLayout());

        forwardModel = new ForwardTableModel();
        forwardTable = new JTable(forwardModel);
        forwardTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        forwardTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        var directionCombo = new JComboBox<>(ForwardDirection.values());
        forwardTable.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(directionCombo));

        var buttons = new JPanel(new MigLayout("insets 8", "[][]push"));
        var addButton = new JButton("Add Forward");
        addButton.addActionListener(e -> forwardModel.addForward());
        var removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> {
            int row = forwardTable.getSelectedRow();
            if (forwardTable.isEditing()) {
                forwardTable.getCellEditor().stopCellEditing();
            }
            if (row >= 0) {
                forwardModel.removeForward(forwardTable.convertRowIndexToModel(row));
            }
        });
        buttons.add(addButton);
        buttons.add(removeButton);

        var hint = new JLabel("<html><small>Local (-L): listens on this engine host. "
                + "Remote (-R): listens on the SSH server.</small></html>");
        var north = new JPanel(new BorderLayout());
        north.add(buttons, BorderLayout.CENTER);
        north.add(hint, BorderLayout.SOUTH);

        panel.add(north, BorderLayout.NORTH);
        panel.add(new JScrollPane(forwardTable), BorderLayout.CENTER);
        return panel;
    }

    private void loadFromTunnel() {
        nameField.setText(tunnel.getName());
        enabledCheck.setSelected(tunnel.isEnabled());
        hostField.setText(tunnel.getHost());
        portSpinner.setValue(tunnel.getPort());
        usernameField.setText(tunnel.getUsername());
        authCombo.setSelectedItem(tunnel.getAuthMethod());
        passwordField.setText(tunnel.getPassword());
        keySourceCombo.setSelectedItem(tunnel.getKeySource());
        keyPathField.setText(tunnel.getPrivateKeyPath());
        keyPemArea.setText(tunnel.getPrivateKeyPem());
        passphraseField.setText(tunnel.getPrivateKeyPassphrase());
        verifyHostKeyCheck.setSelected(tunnel.isVerifyHostKey());
        keepAliveSpinner.setValue(tunnel.getServerAliveIntervalSeconds());
        keepAliveCountSpinner.setValue(tunnel.getServerAliveCountMax());
        forwardModel.setForwards(tunnel.getForwards());
        renderAcceptedHostKey();
    }

    private void renderAcceptedHostKey() {
        if (tunnel.getAcceptedHostKey() != null && !tunnel.getAcceptedHostKey().isEmpty()) {
            hostKeyLabel.setText("Accepted: " + tunnel.getAcceptedHostKeyType());
        } else {
            hostKeyLabel.setText("No host key accepted");
        }
    }

    private void updateAuthVisibility() {
        boolean password = authCombo.getSelectedItem() == AuthMethod.PASSWORD;
        passwordPanel.setVisible(password);
        keyPanel.setVisible(!password);
        if (!password) {
            boolean file = keySourceCombo.getSelectedItem() == KeySource.FILE;
            keyPathPanel.setVisible(file);
            keyPemPanel.setVisible(!file);
        }
        revalidate();
        repaint();
    }

    private void updateHostKeyState() {
        boolean verify = verifyHostKeyCheck.isSelected();
        fetchHostKeyButton.setEnabled(verify);
        hostKeyLabel.setEnabled(verify);
    }

    private void fetchHostKey() {
        var host = hostField.getText().trim();
        int port = (int) portSpinner.getValue();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter the SSH host first.", "Host required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        fetchHostKeyButton.setEnabled(false);
        new SwingWorker<HostKeyInfo, Void>() {
            @Override
            protected HostKeyInfo doInBackground() throws Exception {
                return servlet.fetchHostKey(host, port);
            }

            @Override
            protected void done() {
                try {
                    var info = get();
                    int choice = JOptionPane.showConfirmDialog(SshTunnelDialog.this,
                            "Host: " + host + ":" + port + "\nKey type: " + info.getKeyType()
                                    + "\nFingerprint: " + info.getFingerprint()
                                    + "\n\nAccept this host key?",
                            "Verify Host Key", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                    if (choice == JOptionPane.YES_OPTION) {
                        tunnel.setAcceptedHostKey(info.getPublicKey());
                        tunnel.setAcceptedHostKeyType(info.getKeyType());
                        renderAcceptedHostKey();
                    }
                } catch (Exception e) {
                    log.error("Failed to fetch host key", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelDialog.this, e);
                } finally {
                    fetchHostKeyButton.setEnabled(verifyHostKeyCheck.isSelected());
                }
            }
        }.execute();
    }

    private void testConnection() {
        if (forwardTable.isEditing()) {
            forwardTable.getCellEditor().stopCellEditing();
        }
        var candidate = collectIntoCopy();
        testButton.setEnabled(false);
        new SwingWorker<DiagnosticResult, Void>() {
            @Override
            protected DiagnosticResult doInBackground() throws Exception {
                return servlet.testConnection(candidate);
            }

            @Override
            protected void done() {
                try {
                    new DiagnosticResultDialog(SshTunnelDialog.this, get()).setVisible(true);
                } catch (Exception e) {
                    log.error("Test connection failed", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelDialog.this, e);
                } finally {
                    testButton.setEnabled(true);
                }
            }
        }.execute();
    }

    private void onSave() {
        if (forwardTable.isEditing()) {
            forwardTable.getCellEditor().stopCellEditing();
        }
        var error = validateLocally();
        if (error != null) {
            JOptionPane.showMessageDialog(this, error, "Invalid tunnel", JOptionPane.WARNING_MESSAGE);
            return;
        }
        collectInto(tunnel);
        saved = true;
        dispose();
    }

    private void onCancel() {
        saved = false;
        dispose();
    }

    /**
     * Validation mirrors the server's rules so the admin gets fast feedback and,
     * critically, so a server-only rejection cannot fire after the dialog has
     * already disposed and discarded everything the admin typed.
     */
    private String validateLocally() {
        if (nameField.getText().isBlank()) {
            return "Name is required.";
        }
        if (existingNames.contains(nameField.getText().trim().toLowerCase())) {
            return "A tunnel named '" + nameField.getText().trim() + "' already exists.";
        }
        if (hostField.getText().isBlank()) {
            return "SSH host is required.";
        }
        if (usernameField.getText().isBlank()) {
            return "Username is required.";
        }
        var auth = (AuthMethod) authCombo.getSelectedItem();
        if (auth == AuthMethod.PASSWORD) {
            if (passwordField.getPassword().length == 0) {
                return "Password is required for password authentication.";
            }
        } else if (keySourceCombo.getSelectedItem() == KeySource.FILE) {
            if (keyPathField.getText().isBlank()) {
                return "Private key path is required.";
            }
        } else if (keyPemArea.getText().isBlank()) {
            return "Private key is required.";
        }
        if (verifyHostKeyCheck.isSelected()
                && (tunnel.getAcceptedHostKey() == null || tunnel.getAcceptedHostKey().isEmpty())) {
            return "Host key verification is enabled but no host key has been accepted."
                    + " Fetch and accept the host key, or turn off verification.";
        }
        for (var forward : forwardModel.getForwards()) {
            if (forward.getBindHost().isBlank()) {
                return "Every forward needs a bind host.";
            }
            if (forward.getBindPort() < 1 || forward.getBindPort() > 65535) {
                return "Every forward needs a bind port between 1 and 65535.";
            }
            if (forward.getDestinationHost().isBlank()) {
                return "Every forward needs a destination host.";
            }
            if (forward.getDestinationPort() < 1 || forward.getDestinationPort() > 65535) {
                return "Every forward needs a destination port between 1 and 65535.";
            }
        }
        return null;
    }

    private SshTunnel collectIntoCopy() {
        var copy = tunnel.copy();
        collectInto(copy);
        return copy;
    }

    private void collectInto(SshTunnel target) {
        target.setName(nameField.getText().trim());
        target.setEnabled(enabledCheck.isSelected());
        target.setHost(hostField.getText().trim());
        target.setPort((int) portSpinner.getValue());
        target.setUsername(usernameField.getText().trim());
        target.setAuthMethod((AuthMethod) authCombo.getSelectedItem());
        target.setPassword(new String(passwordField.getPassword()));
        target.setKeySource((KeySource) keySourceCombo.getSelectedItem());
        target.setPrivateKeyPath(keyPathField.getText().trim());
        target.setPrivateKeyPem(keyPemArea.getText());
        target.setPrivateKeyPassphrase(new String(passphraseField.getPassword()));
        target.setVerifyHostKey(verifyHostKeyCheck.isSelected());
        target.setServerAliveIntervalSeconds((int) keepAliveSpinner.getValue());
        target.setServerAliveCountMax((int) keepAliveCountSpinner.getValue());
        target.setForwards(forwardModel.getForwards());
    }
}
