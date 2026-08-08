/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import com.mirth.connect.server.controllers.ConfigurationController;

/**
 * ConfigStore backed by the engine: properties in the CONFIGURATION table under
 * this plugin's group, secrets through the engine's configured encryptor.
 */
public class EngineConfigStore implements ConfigStore {

    private static final String GROUP = SshTunnelServletInterface.PLUGIN_NAME;

    @Override
    public String getProperty(String name) {
        return ConfigurationController.getInstance().getProperty(GROUP, name);
    }

    @Override
    public void saveProperty(String name, String value) {
        ConfigurationController.getInstance().saveProperty(GROUP, name, value);
    }

    @Override
    public String encrypt(String value) {
        return ConfigurationController.getInstance().getEncryptor().encrypt(value);
    }

    @Override
    public String decrypt(String value) {
        return ConfigurationController.getInstance().getEncryptor().decrypt(value);
    }
}
