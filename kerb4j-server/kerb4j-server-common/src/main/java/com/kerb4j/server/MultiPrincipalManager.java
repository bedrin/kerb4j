package com.kerb4j.server;

import com.kerb4j.client.SpnegoClient;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Collection;

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
 */
@NullMarked
public interface MultiPrincipalManager {

    /**
     * Get the {@link SpnegoClient} for the specified service principal name.
     *
     * <p>Implementations may return a configured fallback/default client when no exact match
     * exists for the provided SPN.
     *
     * @param spn the canonical service principal name (e.g. {@code HTTP/host@REALM}); may be
     *            {@code null} when SPN extraction failed
     * @return the {@link SpnegoClient} selected for this SPN, or {@code null} if no principal
     * is configured for it
     */
    @Nullable SpnegoClient getSpnegoClientForSpn(@Nullable String spn);

    /**
     * Check whether this manager has a principal configured for the given SPN.
     *
     * @param spn the canonical service principal name
     * @return {@code true} if a principal is configured for this SPN
     */
    boolean hasPrincipalForSpn(String spn);

    /**
     * Get all configured service principal names.
     *
     * @return configured exact-match SPNs; never {@code null}
     */
    Collection<String> getConfiguredSpns();

    /**
     * Get the configured default/fallback client, if any.
     *
     * @return the configured default/fallback client, or {@code null} if fallback is disabled
     */
    @Nullable SpnegoClient getDefaultSpnegoClient();
}
