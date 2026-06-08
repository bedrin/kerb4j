package com.kerb4j.client.spi;

/**
 * Creates SPNEGO client backends for a specific Kerberos implementation.
 */
public interface SpnegoClientProvider {

    String getName();

    SpnegoClientBackend loginWithUsernamePassword(String username, String password);

    default SpnegoClientBackend loginWithEnterprisePrincipal(String enterprisePrincipal, String password) {
        throw new UnsupportedOperationException("Enterprise principal login is not supported by this SPNEGO provider");
    }

    SpnegoClientBackend loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly);

    SpnegoClientBackend loginWithTicketCache(String principal);
}
