package com.kerb4j.integration.api;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for KerberosClientProvider service discovery
 */
public class KerberosClientProviderTest {

    @Test
    public void testServiceDiscovery() {
        // Test that we can discover available implementations
        // For now, just test that the provider doesn't throw exceptions
        try {
            KerberosClientProvider.resetDefaultFactory();
            // This might throw IllegalStateException if no implementation is found on classpath
            // which is expected in this test environment
        } catch (IllegalStateException e) {
            // Expected when no implementations are on the classpath
            assertTrue(e.getMessage().contains("No KerberosClientFactory implementation found"));
        }
    }

    @Test 
    public void testFactorySelection() {
        // Test manual factory setting
        KerberosClientFactory mockFactory = new KerberosClientFactory() {
            @Override
            public KerberosClient loginWithUsernamePassword(String username, String password) {
                return null;
            }

            @Override
            public KerberosClient loginWithUsernamePassword(String username, String password, boolean useCache) {
                return null;
            }

            @Override
            public KerberosClient loginWithKeyTab(String principal, String keyTabLocation) {
                return null;
            }

            @Override
            public KerberosClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
                return null;
            }

            @Override
            public KerberosClient loginWithTicketCache(String principal) {
                return null;
            }

            @Override
            public String getImplementationName() {
                return "Test";
            }
        };

        KerberosClientProvider.setDefaultFactory(mockFactory);
        assertEquals(mockFactory, KerberosClientProvider.getDefaultFactory());
        assertEquals("Test", KerberosClientProvider.getDefaultFactory().getImplementationName());
        
        // Clean up
        KerberosClientProvider.resetDefaultFactory();
    }
}