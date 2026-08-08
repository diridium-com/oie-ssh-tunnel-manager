/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;

/**
 * The engine deletes a plugin's CONFIGURATION rows on uninstall by
 * CATEGORY = the plugin.xml &lt;name&gt;. Our config is stored under
 * PLUGIN_NAME, so if the two ever diverge, uninstall would orphan every stored
 * tunnel (secrets included). This locks them together.
 */
class PluginNameMatchesConfigGroupTest {

    @Test
    void pluginXmlNameEqualsConfigGroup() throws Exception {
        var file = new File("resources/plugin.xml");
        assertTrue(file.exists(), "plugin.xml not found at " + file.getAbsolutePath());

        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var doc = factory.newDocumentBuilder().parse(file);

        var name = doc.getElementsByTagName("name").item(0).getTextContent().trim();
        assertEquals(SshTunnelServletInterface.PLUGIN_NAME, name,
                "plugin.xml <name> must equal PLUGIN_NAME so uninstall cleans up the config");
    }
}
