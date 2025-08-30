package com.kerb4j.server.spring.integration;

import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test demonstrating multi-principal configuration.
 * This test shows how to configure multiple principals for a single validator.
 */
public class MultiPrincipalConfigurationExample {

    @Test
    public void testMultiPrincipalConfiguration() throws Exception {
        // Create temporary keytab files for testing
        File tempKeytab1 = File.createTempFile("server1", ".keytab");
        File tempKeytab2 = File.createTempFile("server2", ".keytab");
        tempKeytab1.deleteOnExit();
        tempKeytab2.deleteOnExit();
        
        // Create multi-principal manager
        SimpleMultiPrincipalManager multiPrincipalManager = new SimpleMultiPrincipalManager();
        
        // This would normally work with real keytabs, but will fail here since we don't have valid ones
        // The test demonstrates the configuration pattern
        
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(multiPrincipalManager);
        
        // Test that multi-principal mode is properly detected
        assertThrows(Exception.class, () -> {
            validator.afterPropertiesSet(); // This should fail because no principals are configured
        });
        
        // Test that the configuration methods exist
        assertTrue(multiPrincipalManager.getConfiguredSPNs().length == 0);
        assertFalse(multiPrincipalManager.hasPrincipalForSPN("HTTP/www1.server.com@EXAMPLE.COM"));
    }

    @Test 
    public void testSinglePrincipalBackwardCompatibility() throws IOException {
        // Test that single principal configuration still works
        File tempKeytab = File.createTempFile("single", ".keytab");
        tempKeytab.deleteOnExit();
        
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal("HTTP/localhost@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(tempKeytab));
        
        // The configuration is valid, even if the keytab is empty
        // Just test that the setup completes without throwing
        assertDoesNotThrow(() -> {
            validator.afterPropertiesSet();
        });
    }
}

/**
 * Example of how to configure multiple principals in practice.
 * This would be used in actual application configuration.
 */
class MultiPrincipalExampleConfiguration {
    
    public SunJaasKerberosTicketValidator createMultiPrincipalValidator() throws IOException {
        // Create the multi-principal manager
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        
        // Add multiple principals with their respective keytabs
        manager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM", 
                             new FileSystemResource("/etc/keytabs/www1.keytab"));
        manager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM", 
                             new FileSystemResource("/etc/keytabs/www2.keytab"));
        
        // Configure the validator to use multi-principal mode
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(manager);
        
        return validator;
    }
}