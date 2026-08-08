/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.Properties;

import com.mirth.connect.client.core.TaskConstants;
import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.plugins.ServicePlugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server-side plugin entry point: starts the tunnel service on server startup
 * and publishes this plugin's permissions to RBAC.
 */
public class SshTunnelServicePlugin implements ServicePlugin {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelServicePlugin.class);

    @Override
    public String getPluginPointName() {
        return SshTunnelServletInterface.PLUGIN_NAME;
    }

    @Override
    public void init(Properties properties) {
        // Called during server initialization
    }

    @Override
    public void start() {
        log.info("Starting SSH Tunnel Manager plugin");
        SerializationController.registerSerializableClasses();
        var factory = new JschConnectionFactory();
        SshTunnelService.init(new SshTunnelService(new EngineConfigStore(), new TunnelManager(factory), factory));
    }

    @Override
    public void stop() {
        log.info("Stopping SSH Tunnel Manager plugin");
        SshTunnelService.shutdown();
    }

    @Override
    public void update(Properties properties) {
        // No runtime property updates needed
    }

    @Override
    public Properties getDefaultProperties() {
        return new Properties();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        // Operation names are derived by reflection so an operation added to the
        // servlet interface later cannot ship unregistered. The settings-tab
        // composite task name lets RBAC hide the tab from users without view.
        return new ExtensionPermission[] {
                new ExtensionPermission(
                        SshTunnelServletInterface.PLUGIN_NAME,
                        SshTunnelPermissions.VIEW,
                        "View SSH tunnels and their connection status",
                        OperationUtil.getOperationNamesForPermission(
                                SshTunnelPermissions.VIEW, SshTunnelServletInterface.class),
                        new String[] {
                                TaskConstants.SETTINGS_KEY_PREFIX + SshTunnelServletInterface.PLUGIN_NAME
                                        + "/" + TaskConstants.SETTINGS_REFRESH
                        }),
                new ExtensionPermission(
                        SshTunnelServletInterface.PLUGIN_NAME,
                        SshTunnelPermissions.MANAGE,
                        "Create, edit, delete, start, and stop SSH tunnels",
                        OperationUtil.getOperationNamesForPermission(
                                SshTunnelPermissions.MANAGE, SshTunnelServletInterface.class),
                        new String[0])
        };
    }
}
