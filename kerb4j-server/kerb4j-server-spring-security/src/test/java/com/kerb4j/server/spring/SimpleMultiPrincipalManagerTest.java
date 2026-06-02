package com.kerb4j.server.spring;

import com.kerb4j.client.SpnegoClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;

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
        manager.addPrincipal(spn, new FileSystemResource(keytab));

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

        manager.addPrincipal("HTTP/service.example.com@EXAMPLE.COM", new FileSystemResource(serviceKeytab));
        manager.addDefaultPrincipal("HTTP/default.example.com@EXAMPLE.COM", new FileSystemResource(defaultKeytab));

        SpnegoClient fallbackClient = manager.getDefaultSpnegoClient();
        assertNotNull(fallbackClient);
        assertSame(fallbackClient, manager.getSpnegoClientForSpn("HTTP/unknown.example.com@EXAMPLE.COM"));
        assertSame(fallbackClient, manager.getSpnegoClientForSpn(null));
    }

    @Test
    void addPrincipalRejectsInvalidInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal(null, new FileSystemResource("/tmp/dummy.keytab")));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("   ", new FileSystemResource("/tmp/dummy.keytab")));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@EXAMPLE.COM", null));
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@EXAMPLE.COM", new ClassPathResource("inside-jar.keytab")));
    }

    @Test
    void keytabPathResolutionSupportsSpaces() throws IOException {
        File directoryWithSpace = Files.createTempDirectory("kerb4j keytabs").toFile();
        File keytab = File.createTempFile("server keytab", ".keytab", directoryWithSpace);
        directoryWithSpace.deleteOnExit();
        keytab.deleteOnExit();

        String resolvedPath = new FileSystemResource(keytab).getFile().getAbsolutePath();
        assertTrue(resolvedPath.contains(" "));
        assertFalse(resolvedPath.contains("%20"));

        assertDoesNotThrow(() -> manager.addPrincipal("HTTP/space.example.com@EXAMPLE.COM", new FileSystemResource(keytab)));
    }
}
