package com.kerb4j.integration.api;

import javax.security.auth.login.LoginException;

/**
 * Factory interface for creating Kerberos client instances.
 * Implementations provide different Kerberos backends (JDK, Apache Kerby, etc.)
 */
public interface KerberosClientFactory {

    /**
     * Create a client instance using username and password authentication.
     * @param username the username
     * @param password the password
     * @return a new KerberosClient instance
     * @throws Exception if client creation fails
     */
    KerberosClient loginWithUsernamePassword(String username, String password) throws Exception;

    /**
     * Create a client instance using username and password authentication with caching option.
     * @param username the username
     * @param password the password
     * @param useCache whether to cache the client
     * @return a new KerberosClient instance
     * @throws Exception if client creation fails
     */
    KerberosClient loginWithUsernamePassword(String username, String password, boolean useCache) throws Exception;

    /**
     * Create a client instance using keytab authentication.
     * @param principal the principal name
     * @param keyTabLocation the keytab file location
     * @return a new KerberosClient instance
     * @throws Exception if client creation fails
     */
    KerberosClient loginWithKeyTab(String principal, String keyTabLocation) throws Exception;

    /**
     * Create a client instance using keytab authentication with accept-only option.
     * @param principal the principal name
     * @param keyTabLocation the keytab file location
     * @param acceptOnly when true, client works offline for accepting tokens only
     * @return a new KerberosClient instance
     * @throws Exception if client creation fails
     */
    KerberosClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) throws Exception;

    /**
     * Create a client instance using ticket cache authentication.
     * @param principal the principal name
     * @return a new KerberosClient instance
     * @throws Exception if client creation fails
     */
    KerberosClient loginWithTicketCache(String principal) throws Exception;

    /**
     * Get the name/identifier of this Kerberos implementation.
     * @return implementation name (e.g., "JDK", "Apache Kerby")
     */
    String getImplementationName();
}