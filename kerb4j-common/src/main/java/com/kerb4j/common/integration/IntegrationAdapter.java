package com.kerb4j.common.integration;

import com.kerb4j.client.SpnegoClient;

/**
 * Internal adapter class for integration layer.
 * This class is only used when integration modules are available on the classpath.
 */
class IntegrationAdapter {

    /**
     * Create a SpnegoClient using integration layer with username/password.
     */
    static SpnegoClient loginWithUsernamePassword(String username, String password, boolean useCache) {
        try {
            // Use reflection to avoid compile-time dependency on integration modules
            Class<?> providerClass = Class.forName("com.kerb4j.integration.api.KerberosClientProvider");
            Object factory = providerClass.getMethod("getDefaultFactory").invoke(null);
            
            Class<?> factoryClass = Class.forName("com.kerb4j.integration.api.KerberosClientFactory");
            Object kerberosClient = factoryClass.getMethod("loginWithUsernamePassword", String.class, String.class, boolean.class)
                .invoke(factory, username, password, useCache);
            
            // If it's a JDK implementation, extract the underlying SpnegoClient
            if (kerberosClient.getClass().getName().contains("jdk")) {
                Object spnegoClient = kerberosClient.getClass().getMethod("getSpnegoClient").invoke(kerberosClient);
                return (SpnegoClient) spnegoClient;
            } else {
                // For non-JDK implementations, we would need to create an adapter
                // For now, fall back to original implementation
                return SpnegoClient.loginWithUsernamePassword(username, password, useCache);
            }
        } catch (Exception e) {
            // Fall back to original implementation on any error
            return SpnegoClient.loginWithUsernamePassword(username, password, useCache);
        }
    }

    /**
     * Create a SpnegoClient using integration layer with keytab.
     */
    static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
        try {
            Class<?> providerClass = Class.forName("com.kerb4j.integration.api.KerberosClientProvider");
            Object factory = providerClass.getMethod("getDefaultFactory").invoke(null);
            
            Class<?> factoryClass = Class.forName("com.kerb4j.integration.api.KerberosClientFactory");
            Object kerberosClient = factoryClass.getMethod("loginWithKeyTab", String.class, String.class, boolean.class)
                .invoke(factory, principal, keyTabLocation, acceptOnly);
            
            // If it's a JDK implementation, extract the underlying SpnegoClient
            if (kerberosClient.getClass().getName().contains("jdk")) {
                Object spnegoClient = kerberosClient.getClass().getMethod("getSpnegoClient").invoke(kerberosClient);
                return (SpnegoClient) spnegoClient;
            } else {
                // For non-JDK implementations, fall back to original implementation
                return SpnegoClient.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
            }
        } catch (Exception e) {
            // Fall back to original implementation on any error
            return SpnegoClient.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
        }
    }

    /**
     * Create a SpnegoClient using integration layer with ticket cache.
     */
    static SpnegoClient loginWithTicketCache(String principal) {
        try {
            Class<?> providerClass = Class.forName("com.kerb4j.integration.api.KerberosClientProvider");
            Object factory = providerClass.getMethod("getDefaultFactory").invoke(null);
            
            Class<?> factoryClass = Class.forName("com.kerb4j.integration.api.KerberosClientFactory");
            Object kerberosClient = factoryClass.getMethod("loginWithTicketCache", String.class)
                .invoke(factory, principal);
            
            // If it's a JDK implementation, extract the underlying SpnegoClient
            if (kerberosClient.getClass().getName().contains("jdk")) {
                Object spnegoClient = kerberosClient.getClass().getMethod("getSpnegoClient").invoke(kerberosClient);
                return (SpnegoClient) spnegoClient;
            } else {
                // For non-JDK implementations, fall back to original implementation
                return SpnegoClient.loginWithTicketCache(principal);
            }
        } catch (Exception e) {
            // Fall back to original implementation on any error
            return SpnegoClient.loginWithTicketCache(principal);
        }
    }

    /**
     * Get the current implementation name.
     */
    static String getCurrentImplementationName() {
        try {
            Class<?> providerClass = Class.forName("com.kerb4j.integration.api.KerberosClientProvider");
            Object factory = providerClass.getMethod("getDefaultFactory").invoke(null);
            
            Class<?> factoryClass = Class.forName("com.kerb4j.integration.api.KerberosClientFactory");
            return (String) factoryClass.getMethod("getImplementationName").invoke(factory);
        } catch (Exception e) {
            return "JDK";
        }
    }
}