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
