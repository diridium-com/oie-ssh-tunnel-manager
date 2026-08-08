/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;

import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.client.ui.PlatformUI;
import com.mirth.connect.client.ui.components.MirthTable;

import net.miginfocom.swing.MigLayout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Settings panel listing SSH tunnels with live status, appearing as a tab in
 * the OIE Administrator Settings view.
 */
public class SshTunnelSettingsPanel extends AbstractSettingsPanel {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelSettingsPanel.class);

    private SshTunnelServletInterface servlet;
    private MirthTable table;
    private TunnelTableModel tableModel;
    private JButton btnEdit;
    private JButton btnDuplicate;
    private JButton btnDelete;
    private JButton btnStart;
    private JButton btnStop;
    private JButton btnDetails;
    private Map<String, SshTunnelStatus> latestStatuses = Map.of();

    public SshTunnelSettingsPanel(String tabName) {
        super(tabName);
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        tableModel = new TunnelTableModel();
        table = new MirthTable();
        table.setModel(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtonStates();
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRowCount() == 1) {
                    editTunnel();
                }
            }
        });

        var btnNew = new JButton("New");
        btnNew.addActionListener(e -> newTunnel());

        btnEdit = new JButton("Edit");
        btnEdit.setEnabled(false);
        btnEdit.addActionListener(e -> editTunnel());

        btnDuplicate = new JButton("Duplicate");
        btnDuplicate.setEnabled(false);
        btnDuplicate.addActionListener(e -> duplicateTunnel());

        btnDelete = new JButton("Delete");
        btnDelete.setEnabled(false);
        btnDelete.addActionListener(e -> deleteTunnel());

        btnStart = new JButton("Start");
        btnStart.setEnabled(false);
        btnStart.addActionListener(e -> startTunnel());

        btnStop = new JButton("Stop");
        btnStop.setEnabled(false);
        btnStop.addActionListener(e -> stopTunnel());

        btnDetails = new JButton("Details");
        btnDetails.setEnabled(false);
        btnDetails.addActionListener(e -> showDetails());

        var buttonPanel = new JPanel(new MigLayout("insets 0 12 0 12", "[][][][]push[][][]", ""));
        buttonPanel.add(btnNew);
        buttonPanel.add(btnEdit);
        buttonPanel.add(btnDuplicate);
        buttonPanel.add(btnDelete);
        buttonPanel.add(btnStart);
        buttonPanel.add(btnStop);
        buttonPanel.add(btnDetails);

        var topPanel = new JPanel(new MigLayout("insets 0 12 4 12", "[grow]", "[]"));
        topPanel.add(buttonPanel, "growx");

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    @Override
    public void doRefresh() {
        new SwingWorker<Void, Void>() {
            private List<SshTunnel> tunnels;
            private Map<String, SshTunnelStatus> statusMap;

            @Override
            protected Void doInBackground() throws Exception {
                tunnels = getServlet().getTunnels();
                statusMap = new HashMap<>();
                try {
                    for (var status : getServlet().getStatuses()) {
                        statusMap.put(status.getTunnelId(), status);
                    }
                } catch (Exception e) {
                    log.debug("Could not fetch tunnel statuses", e);
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    latestStatuses = statusMap;
                    tableModel.setData(tunnels, statusMap);
                } catch (Exception e) {
                    log.error("Failed to load tunnels", e);
                    latestStatuses = Map.of();
                    tableModel.setData(Collections.emptyList(), Collections.emptyMap());
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
                updateButtonStates();
            }
        }.execute();
    }

    @Override
    public boolean doSave() {
        return true;
    }

    private void updateButtonStates() {
        boolean selected = table.getSelectedRowCount() == 1;
        btnEdit.setEnabled(selected);
        btnDuplicate.setEnabled(selected);
        btnDelete.setEnabled(selected);
        btnStart.setEnabled(selected);
        btnStop.setEnabled(selected);
        btnDetails.setEnabled(selected);
    }

    private void showDetails() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        var status = latestStatuses.get(selected.getId());
        new TunnelDetailDialog(PlatformUI.MIRTH_FRAME, getServlet(), selected.copy(), status).setVisible(true);
    }

    private SshTunnel selectedTunnel() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        return tableModel.getTunnelAt(table.convertRowIndexToModel(viewRow));
    }

    private void newTunnel() {
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), new SshTunnel(), otherNames(null));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), true);
        }
    }

    private void editTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), selected.copy(),
                otherNames(selected.getId()));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), false);
        }
    }

    private void duplicateTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        var copy = selected.copy();
        copy.setId(null);
        copy.setName(selected.getName() + " (copy)");
        // The source came from getTunnels(), so its secrets are the mask string.
        // Sending the mask on create resolves to empty; blank them instead so
        // the admin re-enters real secrets for the new tunnel.
        copy.setPassword("");
        copy.setPrivateKeyPem("");
        copy.setPrivateKeyPassphrase("");
        var dialog = new SshTunnelDialog(PlatformUI.MIRTH_FRAME, getServlet(), copy, otherNames(null));
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            saveTunnel(dialog.getTunnel(), true);
        }
    }

    /** Lowercased names of all tunnels except the one with excludeId, for uniqueness checks. */
    private java.util.Set<String> otherNames(String excludeId) {
        var names = new java.util.HashSet<String>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            var tunnel = tableModel.getTunnelAt(i);
            if (excludeId == null || !excludeId.equals(tunnel.getId())) {
                names.add(tunnel.getName().toLowerCase());
            }
        }
        return names;
    }

    private void saveTunnel(SshTunnel tunnel, boolean isNew) {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                if (isNew) {
                    getServlet().createTunnel(tunnel);
                } else {
                    getServlet().updateTunnel(tunnel.getId(), tunnel);
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                } catch (Exception e) {
                    log.error("Failed to save tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private void deleteTunnel() {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        int choice = JOptionPane.showConfirmDialog(this,
                "Delete tunnel '" + selected.getName() + "'? It will be stopped immediately.",
                "Confirm Delete", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                getServlet().deleteTunnel(selected.getId());
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                } catch (Exception e) {
                    log.error("Failed to delete tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private void startTunnel() {
        runControl(true);
    }

    private void stopTunnel() {
        runControl(false);
    }

    private void runControl(boolean start) {
        var selected = selectedTunnel();
        if (selected == null) {
            return;
        }
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                if (start) {
                    getServlet().startTunnel(selected.getId());
                } else {
                    getServlet().stopTunnel(selected.getId());
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    doRefresh();
                } catch (Exception e) {
                    log.error("Failed to control tunnel", e);
                    PlatformUI.MIRTH_FRAME.alertThrowable(SshTunnelSettingsPanel.this, e);
                }
            }
        }.execute();
    }

    private SshTunnelServletInterface getServlet() {
        if (servlet == null) {
            servlet = PlatformUI.MIRTH_FRAME.mirthClient.getServlet(SshTunnelServletInterface.class);
        }
        return servlet;
    }
}
