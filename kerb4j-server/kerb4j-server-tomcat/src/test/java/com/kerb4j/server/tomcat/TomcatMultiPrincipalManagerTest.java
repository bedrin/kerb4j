package com.kerb4j.server.tomcat;

import com.kerb4j.client.SpnegoClient;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TomcatMultiPrincipalManagerTest {

    @Test
    void explicitFallbackIsUsedForUnknownAndNullSpn() throws Exception {
        File serviceKeytab = File.createTempFile("service", ".keytab");
        File fallbackKeytab = File.createTempFile("fallback", ".keytab");
        serviceKeytab.deleteOnExit();
        fallbackKeytab.deleteOnExit();

        TomcatMultiPrincipalManager manager = new TomcatMultiPrincipalManager();
        manager.addPrincipal("HTTP/service.example.com@EXAMPLE.COM", serviceKeytab.getAbsolutePath());
        manager.addDefaultPrincipal("HTTP/default.example.com@EXAMPLE.COM", fallbackKeytab.getAbsolutePath());

        SpnegoClient defaultClient = manager.getDefaultSpnegoClient();
        assertNotNull(defaultClient);
        assertSame(defaultClient, manager.getSpnegoClientForSpn("HTTP/unknown.example.com@EXAMPLE.COM"));
        assertSame(defaultClient, manager.getSpnegoClientForSpn(null));
    }

    @Test
    void exactSpnResolutionIsCaseSensitiveAndNoImplicitFallback() throws Exception {
        File keytab = File.createTempFile("server", ".keytab");
        keytab.deleteOnExit();

        TomcatMultiPrincipalManager manager = new TomcatMultiPrincipalManager();
        manager.addPrincipal("HTTP/Host.example.com@EXAMPLE.COM", keytab.getAbsolutePath());

        assertNotNull(manager.getSpnegoClientForSpn("HTTP/Host.example.com@EXAMPLE.COM"));
        assertNull(manager.getSpnegoClientForSpn("HTTP/host.example.com@EXAMPLE.COM"));
        assertEquals(1, manager.getConfiguredSpns().size());
        assertTrue(manager.hasPrincipalForSpn("HTTP/Host.example.com@EXAMPLE.COM"));
    }

    @Test
    void invalidPrincipalOrPathIsRejected() {
        TomcatMultiPrincipalManager manager = new TomcatMultiPrincipalManager();
        assertThrows(IllegalArgumentException.class, () -> manager.addPrincipal(null, "/tmp/server.keytab"));
        assertThrows(IllegalArgumentException.class, () -> manager.addPrincipal("  ", "/tmp/server.keytab"));
        assertThrows(IllegalArgumentException.class, () -> manager.addPrincipal("HTTP/server@EXAMPLE.COM", null));
        assertThrows(IllegalArgumentException.class, () -> manager.addPrincipal("HTTP/server@EXAMPLE.COM", " "));
    }
}
