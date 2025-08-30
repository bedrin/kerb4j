package com.kerb4j.server.spring.integration;

import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simple test to verify multi-principal functionality works without full KDC setup.
 * This demonstrates the API and configuration patterns.
 */
public class MultiPrincipalSimpleTest {

    @Test
    public void testMultiPrincipalManagerAPI() throws IOException {
        // Create temporary keytab files for testing
        File tempKeytab1 = File.createTempFile("test1", ".keytab");
        File tempKeytab2 = File.createTempFile("test2", ".keytab");
        tempKeytab1.deleteOnExit();
        tempKeytab2.deleteOnExit();
        
        // Test SimpleMultiPrincipalManager API
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        
        String spn1 = "HTTP/www1.server.com@EXAMPLE.COM";
        String spn2 = "HTTP/www2.server.com@EXAMPLE.COM";
        
        // Initially empty
        assertEquals(0, manager.getConfiguredSPNs().length);
        assertFalse(manager.hasPrincipalForSPN(spn1));
        assertNull(manager.getSpnegoClientForSPN(spn1));
        
        // Test that the API methods work even if configuration fails
        // We're just testing that the methods exist and return expected types
        assertNotNull(manager.getConfiguredSPNs());
        assertEquals(String[].class, manager.getConfiguredSPNs().getClass());
    }

    @Test
    public void testValidatorMultiPrincipalConfiguration() throws Exception {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(manager);
        
        // Should fail because no principals are configured
        Exception exception = assertThrows(Exception.class, () -> {
            validator.afterPropertiesSet();
        });
        
        assertTrue(exception.getMessage().contains("At least one principal must be configured"));
    }

    @Test
    public void testBackwardCompatibility() throws IOException {
        // Test that single principal configuration still works
        File tempKeytab = File.createTempFile("single", ".keytab");
        tempKeytab.deleteOnExit();
        
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal("HTTP/localhost@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));
        
        // Should not throw - configuration is valid even with empty keytab
        assertDoesNotThrow(() -> {
            validator.afterPropertiesSet();
        });
    }

    @Test
    public void testConfigurationMethods() {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        
        // Test method signatures exist and work
        assertNotNull(manager.getConfiguredSPNs());
        assertFalse(manager.hasPrincipalForSPN("test"));
        assertNull(manager.getSpnegoClientForSPN("test"));
        
        // Verify return types
        assertTrue(manager.getConfiguredSPNs() instanceof String[]);
        assertEquals(0, manager.getConfiguredSPNs().length);
    }
}