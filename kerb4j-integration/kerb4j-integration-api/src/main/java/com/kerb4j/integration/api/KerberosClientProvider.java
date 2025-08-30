package com.kerb4j.integration.api;

import java.util.ServiceLoader;

/**
 * Provider for Kerberos client factory implementations.
 * Uses service loader pattern to discover available implementations.
 */
public final class KerberosClientProvider {

    private static volatile KerberosClientFactory defaultFactory;

    private KerberosClientProvider() {
        // Utility class
    }

    /**
     * Get the default Kerberos client factory.
     * This method loads the first available factory using ServiceLoader.
     * @return the default factory
     * @throws IllegalStateException if no factory implementation is found
     */
    public static KerberosClientFactory getDefaultFactory() {
        if (defaultFactory == null) {
            synchronized (KerberosClientProvider.class) {
                if (defaultFactory == null) {
                    ServiceLoader<KerberosClientFactory> loader = ServiceLoader.load(KerberosClientFactory.class);
                    for (KerberosClientFactory factory : loader) {
                        defaultFactory = factory;
                        break;
                    }
                    if (defaultFactory == null) {
                        throw new IllegalStateException("No KerberosClientFactory implementation found on classpath");
                    }
                }
            }
        }
        return defaultFactory;
    }

    /**
     * Get a specific Kerberos client factory by implementation name.
     * @param implementationName the name of the implementation (e.g., "JDK", "Apache Kerby")
     * @return the factory for the specified implementation
     * @throws IllegalArgumentException if no factory with the given name is found
     */
    public static KerberosClientFactory getFactory(String implementationName) {
        ServiceLoader<KerberosClientFactory> loader = ServiceLoader.load(KerberosClientFactory.class);
        for (KerberosClientFactory factory : loader) {
            if (implementationName.equals(factory.getImplementationName())) {
                return factory;
            }
        }
        throw new IllegalArgumentException("No KerberosClientFactory found for implementation: " + implementationName);
    }

    /**
     * Set the default factory (for testing purposes).
     * @param factory the factory to set as default
     */
    public static void setDefaultFactory(KerberosClientFactory factory) {
        synchronized (KerberosClientProvider.class) {
            defaultFactory = factory;
        }
    }

    /**
     * Reset the default factory (for testing purposes).
     */
    public static void resetDefaultFactory() {
        synchronized (KerberosClientProvider.class) {
            defaultFactory = null;
        }
    }
}