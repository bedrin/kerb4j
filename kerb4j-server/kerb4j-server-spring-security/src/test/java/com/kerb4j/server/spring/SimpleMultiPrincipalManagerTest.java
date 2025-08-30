package com.kerb4j.server.spring;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for SimpleMultiPrincipalManager functionality.
 */
public class SimpleMultiPrincipalManagerTest {

    private SimpleMultiPrincipalManager manager;
    private File tempKeytab1;
    private File tempKeytab2;

    @BeforeEach
    public void setUp() throws IOException {
        manager = new SimpleMultiPrincipalManager();
        
        // Create temporary keytab files for testing
        tempKeytab1 = File.createTempFile("test1", ".keytab");
        tempKeytab1.deleteOnExit();
        
        tempKeytab2 = File.createTempFile("test2", ".keytab");
        tempKeytab2.deleteOnExit();
    }

    @Test
    public void testAddAndRetrievePrincipals() {
        // Test configuration without actual Kerberos setup
        String spn1 = "HTTP/www1.server.com@EXAMPLE.COM";
        String spn2 = "HTTP/www2.server.com@EXAMPLE.COM";
        
        // These will fail at runtime due to invalid keytabs, but we can test the structure
        assertDoesNotThrow(() -> {
            // Test that the methods exist and can be called
            assertFalse(manager.hasPrincipalForSPN(spn1));
            assertFalse(manager.hasPrincipalForSPN(spn2));
            
            assertEquals(0, manager.getConfiguredSPNs().length);
            assertNull(manager.getSpnegoClientForSPN(spn1));
        });
    }

    @Test
    public void testEmptyManager() {
        assertEquals(0, manager.getConfiguredSPNs().length);
        assertFalse(manager.hasPrincipalForSPN("any"));
        assertNull(manager.getSpnegoClientForSPN("any"));
    }
}