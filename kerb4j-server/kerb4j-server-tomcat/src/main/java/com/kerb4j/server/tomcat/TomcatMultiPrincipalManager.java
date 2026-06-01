package com.kerb4j.server.tomcat;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple {@link MultiPrincipalManager} implementation for Tomcat that manages
 * multiple service principals, each backed by its own keytab file path.
 *
 * <p>Keytab locations must be absolute paths to local files.
 */
@NullMarked
public class TomcatMultiPrincipalManager implements MultiPrincipalManager {

    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();
    private volatile @Nullable SpnegoClient defaultSpnegoClient;

    /**
     * Add a principal with its keytab file path.
     *
     * @param principal      the canonical service principal name (e.g. {@code HTTP/host@REALM})
     * @param keyTabLocation the absolute path to the keytab file
     * @throws IllegalArgumentException if the principal or keytab path is null or empty
     */
    public void addPrincipal(String principal, String keyTabLocation) {
        spnegoClients.put(principal, createSpnegoClient(principal, keyTabLocation));
    }

    /**
     * Configure an explicit default/fallback principal.
     *
     * @param principal      the fallback service principal name
     * @param keyTabLocation the absolute path to the fallback keytab file
     */
    public void addDefaultPrincipal(String principal, String keyTabLocation) {
        defaultSpnegoClient = createSpnegoClient(principal, keyTabLocation);
    }

    @Override
    public @Nullable SpnegoClient getSpnegoClientForSpn(@Nullable String spn) {
        if (spn == null) {
            return defaultSpnegoClient;
        }
        SpnegoClient spnegoClient = spnegoClients.get(spn);
        return spnegoClient == null ? defaultSpnegoClient : spnegoClient;
    }

    @Override
    public boolean hasPrincipalForSpn(String spn) {
        return spnegoClients.containsKey(spn);
    }

    @Override
    public Collection<String> getConfiguredSpns() {
        return Collections.unmodifiableSet(spnegoClients.keySet());
    }

    @Override
    public @Nullable SpnegoClient getDefaultSpnegoClient() {
        return defaultSpnegoClient;
    }

    private static SpnegoClient createSpnegoClient(String principal, String keyTabLocation) {
        if (principal == null || principal.trim().isEmpty()) {
            throw new IllegalArgumentException("Principal name must not be null or empty");
        }
        if (keyTabLocation == null || keyTabLocation.trim().isEmpty()) {
            throw new IllegalArgumentException("Key tab location must not be null or empty");
        }
        try {
            return SpnegoClient.loginWithKeyTab(principal, keyTabLocation, true);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize principal: " + principal + " with keytab: " + keyTabLocation, e);
        }
    }
}
