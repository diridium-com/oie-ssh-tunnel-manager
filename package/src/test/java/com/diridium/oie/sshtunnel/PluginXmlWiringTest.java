/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;

import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.plugins.SettingsPanelPlugin;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Verifies plugin.xml wires up classes that actually exist and implement the
 * interfaces the engine expects. A ServicePlugin never listed here is dead
 * code the compiler cannot catch, and its permissions simply never register.
 * This module is the only one with server, client, and shared jars all on the
 * classpath, so every declared class can be loaded here.
 */
class PluginXmlWiringTest {

    private Document loadPluginXml() throws Exception {
        var file = new File("resources/plugin.xml");
        assertTrue(file.exists(), "plugin.xml not found at " + file.getAbsolutePath());
        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(file);
    }

    private List<String> textValues(Document doc, String parentTag) {
        var result = new ArrayList<String>();
        var parents = doc.getElementsByTagName(parentTag);
        for (int i = 0; i < parents.getLength(); i++) {
            var strings = ((Element) parents.item(i)).getElementsByTagName("string");
            for (int j = 0; j < strings.getLength(); j++) {
                result.add(strings.item(j).getTextContent().trim());
            }
        }
        return result;
    }

    @Test
    void serverClassIsAServicePlugin() throws Exception {
        var serverClasses = textValues(loadPluginXml(), "serverClasses");
        assertEquals(List.of("com.diridium.oie.sshtunnel.SshTunnelServicePlugin"), serverClasses);

        var clazz = Class.forName(serverClasses.get(0));
        assertTrue(ServicePlugin.class.isAssignableFrom(clazz),
                clazz.getName() + " must implement ServicePlugin");
    }

    @Test
    void clientClassIsASettingsPanelPlugin() throws Exception {
        var clientClasses = textValues(loadPluginXml(), "clientClasses");
        assertEquals(List.of("com.diridium.oie.sshtunnel.SshTunnelSettingsPanelPlugin"), clientClasses);

        var clazz = Class.forName(clientClasses.get(0));
        assertTrue(SettingsPanelPlugin.class.isAssignableFrom(clazz),
                clazz.getName() + " must extend SettingsPanelPlugin");
    }

    @Test
    void apiProvidersResolveToRealClasses() throws Exception {
        var doc = loadPluginXml();
        var providers = doc.getElementsByTagName("apiProvider");
        assertEquals(2, providers.getLength());

        for (int i = 0; i < providers.getLength(); i++) {
            var element = (Element) providers.item(i);
            var type = element.getAttribute("type");
            var name = element.getAttribute("name");
            var clazz = Class.forName(name);
            if (type.equals("SERVLET_INTERFACE")) {
                assertEquals("com.diridium.oie.sshtunnel.SshTunnelServletInterface", name);
                assertTrue(clazz.isInterface());
            } else if (type.equals("SERVER_CLASS")) {
                assertEquals("com.diridium.oie.sshtunnel.SshTunnelServlet", name);
                assertTrue(SshTunnelServletInterface.class.isAssignableFrom(clazz),
                        "the server class must implement the servlet interface");
            }
        }
    }

    @Test
    void libraryEntriesCoverAllThreeModules() throws Exception {
        var doc = loadPluginXml();
        var libraries = doc.getElementsByTagName("library");
        var types = new ArrayList<String>();
        for (int i = 0; i < libraries.getLength(); i++) {
            var element = (Element) libraries.item(i);
            types.add(element.getAttribute("type"));
            var path = element.getAttribute("path");
            assertTrue(path.startsWith("oie-ssh-tunnel-manager-") && path.endsWith(".jar"),
                    "unexpected library path: " + path);
        }
        assertTrue(types.containsAll(List.of("SERVER", "SHARED", "CLIENT")),
                "library types were " + types);
    }
}
