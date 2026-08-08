/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.plugins.SettingsPanelPlugin;

/**
 * Registers the SSH Tunnel Manager settings panel in the OIE Administrator Settings tab.
 */
public class SshTunnelSettingsPanelPlugin extends SettingsPanelPlugin {

    public SshTunnelSettingsPanelPlugin(String name) {
        super(SshTunnelServletInterface.PLUGIN_NAME);
        SerializationController.registerSerializableClasses();
    }

    @Override
    public String getPluginPointName() {
        return SshTunnelServletInterface.PLUGIN_NAME;
    }

    @Override
    public AbstractSettingsPanel getSettingsPanel() {
        return new SshTunnelSettingsPanel(SshTunnelServletInterface.PLUGIN_NAME);
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    @Override
    public void reset() {
    }
}
