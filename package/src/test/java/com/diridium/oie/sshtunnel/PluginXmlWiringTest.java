/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;

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
 * <p>
 * The engine loads the server side and the Administrator loads the client
 * side, never both in one JVM. The OIE release signs mirth-client and not
 * mirth-server, yet both have classes in com.mirth.connect.plugins, and Java
 * refuses to load one package from jars with different signers. So each side
 * is checked through its own class loader, as at runtime: the test classpath
 * without mirth-client for the server class, and without mirth-server for the
 * client class.
 */
class PluginXmlWiringTest {

    private static final String SERVICE_PLUGIN = "com.mirth.connect.plugins.ServicePlugin";
    private static final String SETTINGS_PANEL_PLUGIN = "com.mirth.connect.plugins.SettingsPanelPlugin";

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

    /** The jar a class file comes from, found without loading the class. */
    private static Path jarOf(String className) throws Exception {
        var url = ClassLoader.getSystemResource(className.replace('.', '/') + ".class");
        assertNotNull(url, className + " is not on the test classpath");
        return Path.of(((JarURLConnection) url.openConnection()).getJarFileURL().toURI());
    }

    /** A class loader over the test classpath minus the jar that holds excludedClass. */
    private static URLClassLoader classpathWithout(String excludedClass) throws Exception {
        var excluded = jarOf(excludedClass);
        var entries = System.getProperty("java.class.path").split(File.pathSeparator);
        var urls = new ArrayList<URL>();
        for (var entry : entries) {
            var path = Path.of(entry).toAbsolutePath();
            if (!path.equals(excluded)) {
                urls.add(path.toUri().toURL());
            }
        }
        assertEquals(entries.length - 1, urls.size(), excluded + " was not found on the test classpath");
        return new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader());
    }

    @Test
    void serverClassIsAServicePlugin() throws Exception {
        var serverClasses = textValues(loadPluginXml(), "serverClasses");
        assertEquals(List.of("com.diridium.oie.sshtunnel.SshTunnelServicePlugin"), serverClasses);

        try (var loader = classpathWithout(SETTINGS_PANEL_PLUGIN)) {
            var clazz = Class.forName(serverClasses.get(0), false, loader);
            assertTrue(Class.forName(SERVICE_PLUGIN, false, loader).isAssignableFrom(clazz),
                    clazz.getName() + " must implement ServicePlugin");
        }
    }

    @Test
    void clientClassIsASettingsPanelPlugin() throws Exception {
        var clientClasses = textValues(loadPluginXml(), "clientClasses");
        assertEquals(List.of("com.diridium.oie.sshtunnel.SshTunnelSettingsPanelPlugin"), clientClasses);

        try (var loader = classpathWithout(SERVICE_PLUGIN)) {
            var clazz = Class.forName(clientClasses.get(0), false, loader);
            assertTrue(Class.forName(SETTINGS_PANEL_PLUGIN, false, loader).isAssignableFrom(clazz),
                    clazz.getName() + " must extend SettingsPanelPlugin");
        }
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
