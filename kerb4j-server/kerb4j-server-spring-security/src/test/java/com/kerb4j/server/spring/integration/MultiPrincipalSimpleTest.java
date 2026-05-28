package com.kerb4j.server.spring.integration;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit-level tests for multi-principal configuration of {@link SunJaasKerberosTicketValidator}.
 * These tests verify initialization logic and mode detection without a live KDC.
 */
public class MultiPrincipalSimpleTest {

    // ---------------------------------------------------------------------------
    // Stub MultiPrincipalManager that returns a pre-built client for a given SPN
    // ---------------------------------------------------------------------------

    /** A do-nothing stub used to satisfy afterPropertiesSet() in multi-principal mode. */
    private static MultiPrincipalManager stubManagerWithSpns(String... spns) {
        return new MultiPrincipalManager() {
            @Override
            public SpnegoClient getSpnegoClientForSpn(String spn) {
                for (String s : spns) {
                    if (s.equals(spn)) return null; // just a stub - no real client
                }
                return null;
            }

            @Override
            public boolean hasPrincipalForSpn(String spn) {
                for (String s : spns) {
                    if (s.equals(spn)) return true;
                }
                return false;
            }

            @Override
            public String[] getConfiguredSpns() {
                return spns;
            }
        };
    }

    // ---------------------------------------------------------------------------
    // afterPropertiesSet() mode detection tests
    // ---------------------------------------------------------------------------

    @Test
    public void pureMultiPrincipalMode_afterPropertiesSetSucceeds() throws Exception {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(stubManagerWithSpns("HTTP/host1@REALM", "HTTP/host2@REALM"));
        // Should not throw - valid multi-principal configuration
        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    @Test
    public void pureMultiPrincipalMode_emptyManagerThrows() {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(stubManagerWithSpns(/* no SPNs */));
        IllegalStateException ex = assertThrows(IllegalStateException.class, validator::afterPropertiesSet);
        assertTrue(ex.getMessage().contains("At least one principal must be configured"),
                "Error message should mention missing principals");
    }

    @Test
    public void neitherSingleNorMultiPrincipal_afterPropertiesSetThrows() {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        // Nothing configured at all
        IllegalStateException ex = assertThrows(IllegalStateException.class, validator::afterPropertiesSet);
        assertTrue(ex.getMessage().contains("multiPrincipalManager") || ex.getMessage().contains("servicePrincipal"),
                "Error should mention the configuration options");
    }

    @Test
    public void singlePrincipalMode_afterPropertiesSetInitializesDefaultClient() throws IOException {
        File tempKeytab = File.createTempFile("single", ".keytab");
        tempKeytab.deleteOnExit();

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal("HTTP/localhost@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));

        // Should succeed - single-principal mode uses the (empty) keytab file
        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    @Test
    public void hybridMode_afterPropertiesSetInitializesBothMultiAndDefaultClient() throws IOException {
        File tempKeytab = File.createTempFile("default", ".keytab");
        tempKeytab.deleteOnExit();

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(stubManagerWithSpns("HTTP/host1@REALM"));
        validator.setServicePrincipal("HTTP/default.host@REALM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));

        // Both multi-principal manager and default keytab are configured → hybrid mode.
        // afterPropertiesSet() must initialize the default spnegoClient (not return early).
        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    // ---------------------------------------------------------------------------
    // SimpleMultiPrincipalManager API tests
    // ---------------------------------------------------------------------------

    @Test
    public void simpleManagerEmptyState() {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        assertEquals(0, manager.getConfiguredSpns().length);
        assertFalse(manager.hasPrincipalForSpn("HTTP/host@REALM"));
        assertNull(manager.getSpnegoClientForSpn("HTTP/host@REALM"));
        assertNotNull(manager.getConfiguredSpns());
    }

    @Test
    public void simpleManagerImplementsMultiPrincipalManager() {
        assertTrue(new SimpleMultiPrincipalManager() instanceof MultiPrincipalManager);
    }
}
