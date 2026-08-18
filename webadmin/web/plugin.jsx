// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Diridium Technologies Inc.

/*
 * SSH Tunnel Manager — web administrator entry.
 *
 * Registers the SSH Tunnel Manager settings tab (the web equivalent of the
 * Swing SshTunnelSettingsPanelPlugin). All UI is client-side; it talks only
 * to the existing engine servlet at /api/extensions/oie-ssh-tunnel-manager.
 * The engine enforces the plugin's viewSshTunnels / manageSshTunnels
 * permissions (published to RBAC via getExtensionPermissions) on every
 * operation; the panel additionally hides mutating buttons via the host's
 * task checks.
 */

import { makeApi } from './ssh-api.js';
import { registerTunnelPanel } from './tunnel-panel.jsx';

export function register(platform) {
    const api = makeApi(platform.api);
    registerTunnelPanel(platform, api);
}
