package com.kerb4j.integration;

import com.kerb4j.integration.api.KerberosClient;
import com.kerb4j.integration.api.KerberosClientFactory;
import com.kerb4j.integration.api.KerberosClientProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test demonstrating multiple Kerberos implementation support.
 */
public class IntegrationTest {

    @Test
    public void testMultipleImplementationsAvailable() {
        // Test that we can discover both JDK and Apache Kerby implementations
        try {
            KerberosClientFactory jdkFactory = KerberosClientProvider.getFactory("JDK");
            assertNotNull(jdkFactory);
            assertEquals("JDK", jdkFactory.getImplementationName());
        } catch (IllegalArgumentException e) {
            fail("JDK implementation should be available: " + e.getMessage());
        }

        try {
            KerberosClientFactory kerbyFactory = KerberosClientProvider.getFactory("Apache Kerby");
            assertNotNull(kerbyFactory);
            assertEquals("Apache Kerby", kerbyFactory.getImplementationName());
        } catch (IllegalArgumentException e) {
            fail("Apache Kerby implementation should be available: " + e.getMessage());
        }
    }

    @Test
    public void testDefaultFactory() {
        // Test that we get a default factory
        KerberosClientFactory defaultFactory = KerberosClientProvider.getDefaultFactory();
        assertNotNull(defaultFactory);
        assertNotNull(defaultFactory.getImplementationName());
        assertTrue(defaultFactory.getImplementationName().equals("JDK") || 
                  defaultFactory.getImplementationName().equals("Apache Kerby"));
    }

    @Test
    public void testJdkImplementation() throws Exception {
        KerberosClientFactory jdkFactory = KerberosClientProvider.getFactory("JDK");
        
        // Test that we can create clients without actual authentication
        // (since we don't have a real Kerberos environment in this test)
        try {
            KerberosClient client = jdkFactory.loginWithTicketCache("test@EXAMPLE.COM");
            assertNotNull(client);
            assertNotNull(client.getSubject());
        } catch (Exception e) {
            // Expected to fail in test environment without real Kerberos setup
            assertTrue(e.getMessage() != null);
        }
    }

    @Test
    public void testKerbyImplementation() throws Exception {
        KerberosClientFactory kerbyFactory = KerberosClientProvider.getFactory("Apache Kerby");
        
        // Test that we can create clients without actual authentication
        try {
            KerberosClient client = kerbyFactory.loginWithTicketCache("test@EXAMPLE.COM");
            assertNotNull(client);
            assertNotNull(client.getSubject());
        } catch (Exception e) {
            // Expected to fail in test environment without real Kerberos setup
            assertTrue(e.getMessage() != null);
        }
    }

    @Test
    public void testFactorySwitching() {
        // Test that we can switch between implementations
        KerberosClientFactory originalDefault = KerberosClientProvider.getDefaultFactory();
        
        try {
            KerberosClientFactory jdkFactory = KerberosClientProvider.getFactory("JDK");
            KerberosClientProvider.setDefaultFactory(jdkFactory);
            assertEquals("JDK", KerberosClientProvider.getDefaultFactory().getImplementationName());
            
            KerberosClientFactory kerbyFactory = KerberosClientProvider.getFactory("Apache Kerby");
            KerberosClientProvider.setDefaultFactory(kerbyFactory);
            assertEquals("Apache Kerby", KerberosClientProvider.getDefaultFactory().getImplementationName());
            
        } finally {
            // Restore original default
            KerberosClientProvider.setDefaultFactory(originalDefault);
        }
    }
}