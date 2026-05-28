package com.kerb4j.server.spring.integration;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Demonstrates multi-principal configuration patterns for {@link SunJaasKerberosTicketValidator}.
 */
public class MultiPrincipalConfigurationExample {

    private static MultiPrincipalManager stubManagerWithOneSpn(String spn) {
        return new MultiPrincipalManager() {
            @Override public SpnegoClient getSpnegoClientForSpn(String s) { return null; }
            @Override public boolean hasPrincipalForSpn(String s) { return spn.equals(s); }
            @Override public String[] getConfiguredSpns() { return new String[]{spn}; }
        };
    }

    @Test
    public void testMultiPrincipalConfiguration() {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(new SimpleMultiPrincipalManager());

        // Should fail because the manager has no principals configured
        IllegalStateException ex = assertThrows(IllegalStateException.class, validator::afterPropertiesSet);
        assertTrue(ex.getMessage().contains("At least one principal must be configured"));
    }

    @Test
    public void testSinglePrincipalBackwardCompatibility() throws IOException {
        File tempKeytab = File.createTempFile("single", ".keytab");
        tempKeytab.deleteOnExit();

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal("HTTP/localhost@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));

        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    @Test
    public void testHybridModePrincipalAlsoConfigured() throws IOException {
        File tempKeytab = File.createTempFile("hybrid-default", ".keytab");
        tempKeytab.deleteOnExit();

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(stubManagerWithOneSpn("HTTP/www1.server.com@EXAMPLE.COM"));
        validator.setServicePrincipal("HTTP/default.server.com@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));

        // Hybrid mode: both multiPrincipalManager and default principal configured.
        // afterPropertiesSet() must initialize both (no early return).
        assertDoesNotThrow(validator::afterPropertiesSet);
    }
}
