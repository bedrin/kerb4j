package com.kerb4j.server.spring;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple implementation of {@link MultiPrincipalManager} that manages multiple
 * service principals, each backed by its own keytab file.
 *
 * <p>Keytab resources must be accessible as local files; non-file resources
 * (e.g. classpath entries inside a JAR) are not supported and will cause an
 * {@link IllegalArgumentException} at configuration time.
 *
 * <p>This class is provided in {@code kerb4j-server-spring-security-core} so
 * that both the servlet (Spring Security MVC) and reactive (Spring WebFlux)
 * stacks can share the same multi-principal configuration building blocks.
 */
@NullMarked
public class SimpleMultiPrincipalManager implements MultiPrincipalManager {

    private final Map<String, SpnegoClient> spnegoClients = new ConcurrentHashMap<>();
    private volatile @Nullable SpnegoClient defaultSpnegoClient;

    /**
     * Add a principal with its keytab resource.
     *
     * @param principal      the canonical service principal name (e.g. {@code HTTP/host@REALM})
     * @param keyTabLocation a Spring {@link Resource} pointing to a local keytab file
     * @param acceptOnly     {@code true} to configure the client in accept-only mode
     * @throws IllegalArgumentException if the principal name or resource is invalid,
     *                                  or if the resource cannot be resolved to a local file
     */
    public void addPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly) {
        spnegoClients.put(principal, createSpnegoClient(principal, keyTabLocation, acceptOnly));
    }

    /**
     * Add a principal with its keytab resource using accept-only mode.
     *
     * @param principal      the canonical service principal name
     * @param keyTabLocation a Spring {@link Resource} pointing to a local keytab file
     */
    public void addPrincipal(String principal, Resource keyTabLocation) {
        addPrincipal(principal, keyTabLocation, true);
    }

    /**
     * Configure an explicit default/fallback principal.
     *
     * @param principal      the fallback service principal name
     * @param keyTabLocation a Spring {@link Resource} pointing to a local keytab file
     * @param acceptOnly     {@code true} to configure the client in accept-only mode
     */
    public void addDefaultPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly) {
        defaultSpnegoClient = createSpnegoClient(principal, keyTabLocation, acceptOnly);
    }

    /**
     * Configure an explicit default/fallback principal in accept-only mode.
     *
     * @param principal      the fallback service principal name
     * @param keyTabLocation a Spring {@link Resource} pointing to a local keytab file
     */
    public void addDefaultPrincipal(String principal, Resource keyTabLocation) {
        addDefaultPrincipal(principal, keyTabLocation, true);
    }

    @Override
    public @Nullable SpnegoClient getSpnegoClientForSpn(@Nullable String spn) {
        if (null == spn) {
            return defaultSpnegoClient;
        }
        SpnegoClient spnegoClient = spnegoClients.get(spn);
        return null == spnegoClient ? defaultSpnegoClient : spnegoClient;
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

    private static SpnegoClient createSpnegoClient(String principal, Resource keyTabLocation, boolean acceptOnly) {
        if (principal == null || principal.trim().isEmpty()) {
            throw new IllegalArgumentException("Principal name must not be null or empty");
        }
        if (keyTabLocation == null) {
            throw new IllegalArgumentException("Key tab location must not be null");
        }
        String keyTabPath;
        try {
            keyTabPath = keyTabLocation.getFile().getAbsolutePath();
        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "Key tab location must be a local file resource (classpath resources inside JARs are not supported): "
                            + keyTabLocation, e);
        }
        try {
            return SpnegoClient.loginWithKeyTab(principal, keyTabPath, acceptOnly);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize principal: " + principal + " with keytab: " + keyTabPath, e);
        }
    }
}
