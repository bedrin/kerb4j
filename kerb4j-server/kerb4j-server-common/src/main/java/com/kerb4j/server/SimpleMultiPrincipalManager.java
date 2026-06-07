package com.kerb4j.server;

import com.kerb4j.client.SpnegoClient;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple {@link MultiPrincipalManager} implementation that manages multiple
 * service principals backed by local keytab files or prebuilt {@link SpnegoClient}s.
 */
@NullMarked
public class SimpleMultiPrincipalManager implements MultiPrincipalManager {

    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();
    private volatile @Nullable SpnegoClient defaultSpnegoClient;

    /**
     * Add a principal with its keytab file path using accept-only mode.
     *
     * @param principal      the canonical service principal name (e.g. {@code HTTP/host@REALM})
     * @param keyTabLocation the local keytab file path
     */
    public void addPrincipal(String principal, String keyTabLocation) {
        addPrincipal(principal, keyTabLocation, true);
    }

    /**
     * Add a principal with its keytab file path.
     *
     * @param principal      the canonical service principal name (e.g. {@code HTTP/host@REALM})
     * @param keyTabLocation the local keytab file path
     * @param acceptOnly     {@code true} to configure the client in accept-only mode
     */
    public void addPrincipal(String principal, String keyTabLocation, boolean acceptOnly) {
        addSpnegoClient(principal, createSpnegoClient(principal, keyTabLocation, acceptOnly));
    }

    /**
     * Add a principal with its keytab file using accept-only mode.
     *
     * @param principal the canonical service principal name
     * @param keyTab    the local keytab file
     */
    public void addPrincipal(String principal, File keyTab) {
        addPrincipal(principal, keyTab, true);
    }

    /**
     * Add a principal with its keytab file.
     *
     * @param principal  the canonical service principal name
     * @param keyTab     the local keytab file
     * @param acceptOnly {@code true} to configure the client in accept-only mode
     */
    public void addPrincipal(String principal, File keyTab, boolean acceptOnly) {
        addPrincipal(principal, resolveKeyTabPath(keyTab), acceptOnly);
    }

    /**
     * Configure an explicit default/fallback principal in accept-only mode.
     *
     * @param principal      the fallback service principal name
     * @param keyTabLocation the local keytab file path
     */
    public void addDefaultPrincipal(String principal, String keyTabLocation) {
        addDefaultPrincipal(principal, keyTabLocation, true);
    }

    /**
     * Configure an explicit default/fallback principal.
     *
     * @param principal      the fallback service principal name
     * @param keyTabLocation the local keytab file path
     * @param acceptOnly     {@code true} to configure the client in accept-only mode
     */
    public void addDefaultPrincipal(String principal, String keyTabLocation, boolean acceptOnly) {
        addDefaultSpnegoClient(createSpnegoClient(principal, keyTabLocation, acceptOnly));
    }

    /**
     * Configure an explicit default/fallback principal in accept-only mode.
     *
     * @param principal the fallback service principal name
     * @param keyTab    the local keytab file
     */
    public void addDefaultPrincipal(String principal, File keyTab) {
        addDefaultPrincipal(principal, keyTab, true);
    }

    /**
     * Configure an explicit default/fallback principal.
     *
     * @param principal  the fallback service principal name
     * @param keyTab     the local keytab file
     * @param acceptOnly {@code true} to configure the client in accept-only mode
     */
    public void addDefaultPrincipal(String principal, File keyTab, boolean acceptOnly) {
        addDefaultPrincipal(principal, resolveKeyTabPath(keyTab), acceptOnly);
    }

    /**
     * Add a prebuilt client for a canonical service principal name.
     *
     * @param principal    the canonical service principal name
     * @param spnegoClient the client to use for tokens targeting this principal
     */
    public void addSpnegoClient(String principal, SpnegoClient spnegoClient) {
        if (principal == null || principal.trim().isEmpty()) {
            throw new IllegalArgumentException("Principal name must not be null or empty");
        }
        if (spnegoClient == null) {
            throw new IllegalArgumentException("SPNEGO client must not be null");
        }
        spnegoClients.put(principal, spnegoClient);
    }

    /**
     * Configure a prebuilt default/fallback client.
     *
     * @param spnegoClient the fallback client
     */
    public void addDefaultSpnegoClient(SpnegoClient spnegoClient) {
        if (spnegoClient == null) {
            throw new IllegalArgumentException("SPNEGO client must not be null");
        }
        defaultSpnegoClient = spnegoClient;
    }

    /**
     * Add every principal found in a keytab file path using accept-only clients.
     *
     * @param keyTabLocation the local keytab file path
     * @return the principals registered from the keytab
     */
    public Collection<String> addPrincipalsFromKeytab(String keyTabLocation) {
        return addPrincipalsFromKeytab(keyTabLocation, true);
    }

    /**
     * Add every principal found in a keytab file path.
     *
     * @param keyTabLocation the local keytab file path
     * @param acceptOnly     {@code true} to configure each client in accept-only mode
     * @return the principals registered from the keytab
     */
    public Collection<String> addPrincipalsFromKeytab(String keyTabLocation, boolean acceptOnly) {
        Collection<String> principals = KeytabPrincipalReader.getPrincipals(keyTabLocation);
        for (String principal : principals) {
            addPrincipal(principal, keyTabLocation, acceptOnly);
        }
        return principals;
    }

    /**
     * Add every principal found in a keytab file using accept-only clients.
     *
     * @param keyTab the local keytab file
     * @return the principals registered from the keytab
     */
    public Collection<String> addPrincipalsFromKeytab(File keyTab) {
        return addPrincipalsFromKeytab(keyTab, true);
    }

    /**
     * Add every principal found in a keytab file.
     *
     * @param keyTab     the local keytab file
     * @param acceptOnly {@code true} to configure each client in accept-only mode
     * @return the principals registered from the keytab
     */
    public Collection<String> addPrincipalsFromKeytab(File keyTab, boolean acceptOnly) {
        return addPrincipalsFromKeytab(resolveKeyTabPath(keyTab), acceptOnly);
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

    private static SpnegoClient createSpnegoClient(String principal, String keyTabLocation, boolean acceptOnly) {
        if (principal == null || principal.trim().isEmpty()) {
            throw new IllegalArgumentException("Principal name must not be null or empty");
        }
        if (keyTabLocation == null || keyTabLocation.trim().isEmpty()) {
            throw new IllegalArgumentException("Key tab location must not be null or empty");
        }
        try {
            return SpnegoClient.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize principal: " + principal + " with keytab: " + keyTabLocation, e);
        }
    }

    private static String resolveKeyTabPath(File keyTab) {
        if (keyTab == null) {
            throw new IllegalArgumentException("Key tab file must not be null");
        }
        return keyTab.getAbsolutePath();
    }
}
