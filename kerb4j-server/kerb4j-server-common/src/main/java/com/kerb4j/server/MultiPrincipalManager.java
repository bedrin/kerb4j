/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
