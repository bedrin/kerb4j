package com.kerb4j.server;

import com.kerb4j.client.SpnegoClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class SimpleMultiPrincipalManagerTest {

    private SimpleMultiPrincipalManager manager;

    @BeforeEach
    void setUp() {
        manager = new SimpleMultiPrincipalManager();
    }

    @Test
    void emptyManagerFailsClosedWithoutFallback() {
        Collection<String> configuredSpns = manager.getConfiguredSpns();
        assertEquals(0, configuredSpns.size());
        assertFalse(manager.hasPrincipalForSpn("HTTP/host@EXAMPLE.COM"));
        assertNull(manager.getDefaultSpnegoClient());
        assertNull(manager.getSpnegoClientForSpn("HTTP/host@EXAMPLE.COM"));
        assertNull(manager.getSpnegoClientForSpn(null));
    }

    @Test
    void addPrincipalStoresExactCaseSensitiveSpn() throws IOException {
        File keytab = File.createTempFile("server", ".keytab");
        keytab.deleteOnExit();

        String spn = "HTTP/Host.EXAMPLE.COM@EXAMPLE.COM";
        manager.addPrincipal(spn, keytab);

        SpnegoClient resolvedClient = manager.getSpnegoClientForSpn(spn);
        assertNotNull(resolvedClient);
        assertTrue(manager.hasPrincipalForSpn(spn));
        assertFalse(manager.hasPrincipalForSpn("HTTP/host.example.com@EXAMPLE.COM"));
        assertNull(manager.getSpnegoClientForSpn("HTTP/host.example.com@EXAMPLE.COM"));
    }

    @Test
    void unknownOrNullSpnUsesExplicitFallbackWhenConfigured() throws IOException {
        File serviceKeytab = File.createTempFile("service", ".keytab");
        File defaultKeytab = File.createTempFile("default", ".keytab");
        serviceKeytab.deleteOnExit();
        defaultKeytab.deleteOnExit();

        manager.addPrincipal("HTTP/service.example.com@EXAMPLE.COM", serviceKeytab);
        manager.addDefaultPrincipal("HTTP/default.example.com@EXAMPLE.COM", defaultKeytab);

        SpnegoClient fallbackClient = manager.getDefaultSpnegoClient();
        assertNotNull(fallbackClient);
        assertSame(fallbackClient, manager.getSpnegoClientForSpn("HTTP/unknown.example.com@EXAMPLE.COM"));
        assertSame(fallbackClient, manager.getSpnegoClientForSpn(null));
    }

    @Test
    void addSpnegoClientStoresPrebuiltClient() throws IOException {
        File keytab = File.createTempFile("prebuilt", ".keytab");
        keytab.deleteOnExit();

        String spn = "HTTP/prebuilt.example.com@EXAMPLE.COM";
        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(spn, keytab.getAbsolutePath(), true);

        manager.addSpnegoClient(spn, spnegoClient);
        manager.addDefaultSpnegoClient(spnegoClient);

        assertSame(spnegoClient, manager.getSpnegoClientForSpn(spn));
        assertSame(spnegoClient, manager.getDefaultSpnegoClient());
    }

    @Test
    void addPrincipalRejectsInvalidInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal(null, "/tmp/dummy.keytab"));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("   ", "/tmp/dummy.keytab"));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@EXAMPLE.COM", (String) null));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@EXAMPLE.COM", " "));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@EXAMPLE.COM", (File) null));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addSpnegoClient("HTTP/host@EXAMPLE.COM", null));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addDefaultSpnegoClient(null));
    }

    @Test
    void keytabPathResolutionSupportsSpaces() throws IOException {
        File directoryWithSpace = Files.createTempDirectory("kerb4j keytabs").toFile();
        File keytab = File.createTempFile("server keytab", ".keytab", directoryWithSpace);
        directoryWithSpace.deleteOnExit();
        keytab.deleteOnExit();

        String resolvedPath = keytab.getAbsolutePath();
        assertTrue(resolvedPath.contains(" "));
        assertFalse(resolvedPath.contains("%20"));

        assertDoesNotThrow(() -> manager.addPrincipal("HTTP/space.example.com@EXAMPLE.COM", keytab));
    }
}
