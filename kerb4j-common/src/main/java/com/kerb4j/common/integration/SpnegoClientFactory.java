package com.kerb4j.common.integration;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;

import java.net.URL;
import java.security.PrivilegedActionException;

/**
 * Factory class that provides SpnegoClient instances with optional integration layer support.
 * This allows users to switch between different Kerberos implementations if integration modules
 * are available on the classpath, while maintaining backward compatibility.
 */
public class SpnegoClientFactory {

    private static final String INTEGRATION_API_CLASS = "com.kerb4j.integration.api.KerberosClientProvider";
    private static final boolean INTEGRATION_AVAILABLE = isIntegrationAvailable();

    private static boolean isIntegrationAvailable() {
        try {
            Class.forName(INTEGRATION_API_CLASS);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Create a SpnegoClient using username and password.
     * Uses integration layer if available, otherwise falls back to original implementation.
     * 
     * @param username the username
     * @param password the password
     * @return SpnegoClient instance
     */
    public static SpnegoClient loginWithUsernamePassword(String username, String password) {
        return loginWithUsernamePassword(username, password, false);
    }

    /**
     * Create a SpnegoClient using username and password with caching option.
     * Uses integration layer if available, otherwise falls back to original implementation.
     * 
     * @param username the username
     * @param password the password
     * @param useCache whether to cache the client
     * @return SpnegoClient instance
     */
    public static SpnegoClient loginWithUsernamePassword(String username, String password, boolean useCache) {
        if (INTEGRATION_AVAILABLE) {
            return IntegrationAdapter.loginWithUsernamePassword(username, password, useCache);
        } else {
            return SpnegoClient.loginWithUsernamePassword(username, password, useCache);
        }
    }

    /**
     * Create a SpnegoClient using keytab authentication.
     * Uses integration layer if available, otherwise falls back to original implementation.
     * 
     * @param principal the principal name
     * @param keyTabLocation the keytab file location
     * @return SpnegoClient instance
     */
    public static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation) {
        return loginWithKeyTab(principal, keyTabLocation, false);
    }

    /**
     * Create a SpnegoClient using keytab authentication with accept-only option.
     * Uses integration layer if available, otherwise falls back to original implementation.
     * 
     * @param principal the principal name
     * @param keyTabLocation the keytab file location
     * @param acceptOnly when true, client works offline for accepting tokens only
     * @return SpnegoClient instance
     */
    public static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
        if (INTEGRATION_AVAILABLE) {
            return IntegrationAdapter.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
        } else {
            return SpnegoClient.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
        }
    }

    /**
     * Create a SpnegoClient using ticket cache authentication.
     * Uses integration layer if available, otherwise falls back to original implementation.
     * 
     * @param principal the principal name
     * @return SpnegoClient instance
     */
    public static SpnegoClient loginWithTicketCache(String principal) {
        if (INTEGRATION_AVAILABLE) {
            return IntegrationAdapter.loginWithTicketCache(principal);
        } else {
            return SpnegoClient.loginWithTicketCache(principal);
        }
    }

    /**
     * Check if integration layer is available on the classpath.
     * @return true if integration modules are available
     */
    public static boolean isIntegrationLayerAvailable() {
        return INTEGRATION_AVAILABLE;
    }

    /**
     * Get the name of the currently used Kerberos implementation.
     * @return implementation name, or "JDK" if integration layer is not available
     */
    public static String getCurrentImplementationName() {
        if (INTEGRATION_AVAILABLE) {
            return IntegrationAdapter.getCurrentImplementationName();
        } else {
            return "JDK";
        }
    }
}