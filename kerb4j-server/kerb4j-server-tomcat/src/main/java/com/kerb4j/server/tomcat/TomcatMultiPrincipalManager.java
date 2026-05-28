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
package com.kerb4j.server.tomcat;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple {@link MultiPrincipalManager} implementation for Tomcat that manages
 * multiple service principals, each backed by its own keytab file path.
 *
 * <p>Keytab locations must be absolute paths to local files.
 *
 * @since 2.0.0
 */
public class TomcatMultiPrincipalManager implements MultiPrincipalManager {

    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();

    /**
     * Add a principal with its keytab file path.
     *
     * @param principal      the canonical service principal name (e.g. {@code HTTP/host@REALM})
     * @param keyTabLocation the absolute path to the keytab file
     * @throws IllegalArgumentException if the principal or keytab path is null or empty
     */
    public void addPrincipal(String principal, String keyTabLocation) {
        if (principal == null || principal.trim().isEmpty()) {
            throw new IllegalArgumentException("Principal name must not be null or empty");
        }
        if (keyTabLocation == null || keyTabLocation.trim().isEmpty()) {
            throw new IllegalArgumentException("Key tab location must not be null or empty");
        }
        try {
            SpnegoClient client = SpnegoClient.loginWithKeyTab(principal, keyTabLocation, true);
            spnegoClients.put(principal, client);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize principal: " + principal + " with keytab: " + keyTabLocation, e);
        }
    }

    @Override
    public SpnegoClient getSpnegoClientForSpn(String spn) {
        if (spn == null) {
            return null;
        }
        return spnegoClients.get(spn);
    }

    @Override
    public boolean hasPrincipalForSpn(String spn) {
        if (spn == null) {
            return false;
        }
        return spnegoClients.containsKey(spn);
    }

    @Override
    public String[] getConfiguredSpns() {
        return spnegoClients.keySet().toArray(new String[0]);
    }
}
