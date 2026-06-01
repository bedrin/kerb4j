package com.kerb4j.server;

import com.kerb4j.client.SpnegoClient;

/**
 * Interface for managing multiple service principals. This allows the server
 * to handle SPNEGO tokens for different service principals (SPNs) and select
 * the appropriate principal based on the target SPN in the token.
 *
 * <p>SPNs must be in canonical form including the realm, for example
 * {@code HTTP/www.example.com@EXAMPLE.COM}.  Lookup is exact-match and
 * case-sensitive; the string must match what
 * {@link com.kerb4j.server.marshall.spnego.SpnegoKerberosMechToken#getServerPrincipalName()}
 * returns for incoming tokens.
 *
 * <p>Implementations must reject null or blank principal names with
 * {@link IllegalArgumentException}.
 *
 * @since 2.0.0
 */
public interface MultiPrincipalManager {

    /**
     * Get the {@link SpnegoClient} for the specified service principal name.
     *
     * @param spn the canonical service principal name (e.g. {@code HTTP/host@REALM}); must not be null
     * @return the {@link SpnegoClient} configured for this SPN, or {@code null} if not found
     */
    SpnegoClient getSpnegoClientForSpn(String spn);

    /**
     * Check whether this manager has a principal configured for the given SPN.
     *
     * @param spn the canonical service principal name; must not be null
     * @return {@code true} if a principal is configured for this SPN
     */
    boolean hasPrincipalForSpn(String spn);

    /**
     * Get all configured service principal names.
     *
     * @return array of configured SPNs; never {@code null}
     */
    String[] getConfiguredSpns();
}
