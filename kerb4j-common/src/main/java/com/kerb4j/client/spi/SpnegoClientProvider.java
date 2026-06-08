package com.kerb4j.client.spi;

/**
 * Creates SPNEGO client backends for a specific Kerberos implementation.
 */
public interface SpnegoClientProvider {

    String getName();

    SpnegoClientBackend loginWithUsernamePassword(String username, String password);

    SpnegoClientBackend loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly);

    SpnegoClientBackend loginWithTicketCache(String principal);
}
