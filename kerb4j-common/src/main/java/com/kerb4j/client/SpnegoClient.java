/**
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package com.kerb4j.client;

import com.kerb4j.client.spi.JaasSubjectSupplier;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.exception.Kerb4JKerberosException;
import com.kerb4j.common.exception.KerberosFailureAnalyzer;
import com.kerb4j.common.util.LRUCache;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginContext;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.AbstractMap;
import java.util.concurrent.Callable;

/**
 * This Class may be used by custom clients as a convenience when connecting
 * to a protected HTTP server.
 *
 * <p>
 * A krb5.conf is required when using this class. Take a
 * look at the <a href="http://spnego.sourceforge.net" target="_blank">spnego.sourceforge.net</a>
 * documentation for an example krb5.conf file.
 * Also, you must provide a keytab file, or a username and password, or allowtgtsessionkey.
 * </p>
 *
 * @author Darwin V. Felix
 */
public final class SpnegoClient {

    public static final String SPNEGO_PROVIDER_PROPERTY = "kerb4j.spnego.provider";

    private static final LRUCache<CacheKey, SpnegoClient> SPNEGO_CLIENT_CACHE = new LRUCache<>(1024);

    private final SpnegoClientBackend backend;

    private SpnegoClient(SpnegoClientBackend backend) {
        this.backend = backend;
    }

    public static void resetCache() {
        synchronized (SPNEGO_CLIENT_CACHE) {
            SPNEGO_CLIENT_CACHE.clear();
        }
        SpnegoClientProviderRegistry.reset();
    }

    /**
     * Creates an instance where authentication is done using username and password.
     * Kerby is used when the Kerby provider module is present; otherwise the JDK/JGSS provider is used. Override with
     * {@code -Dkerb4j.spnego.provider=jdk}, {@code -Dkerb4j.spnego.provider=kerby}, or a provider class name.
     *
     * @param username username
     * @param password password
     */
    public static SpnegoClient loginWithUsernamePassword(final String username, final String password) {
        return loginWithUsernamePassword(username, password, false);
    }

    /**
     * Creates an instance where authentication is done using username and password.
     * Kerby is used when the Kerby provider module is present; otherwise the JDK/JGSS provider is used. Override with
     * {@code -Dkerb4j.spnego.provider=jdk}, {@code -Dkerb4j.spnego.provider=kerby}, or a provider class name.
     *
     * @param username username
     * @param password password
     */
    public static SpnegoClient loginWithUsernamePassword(final String username, final String password, final boolean useCache) {
        SpnegoClientProvider provider = SpnegoClientProviderRegistry.getPreferredProvider();
        if (!useCache) {
            return loginWithUsernamePasswordImpl(provider, username, password);
        }
        CacheKey entry = CacheKey.usernamePassword(provider.getName(), username, password);
        SpnegoClient spnegoClient;
        synchronized (SPNEGO_CLIENT_CACHE) {
            spnegoClient = SPNEGO_CLIENT_CACHE.get(entry);
            if (null == spnegoClient) {
                spnegoClient = loginWithUsernamePasswordImpl(provider, username, password);
                SPNEGO_CLIENT_CACHE.put(entry, spnegoClient);
            }
        }
        return spnegoClient;
    }

    private static SpnegoClient loginWithUsernamePasswordImpl(SpnegoClientProvider provider,
                                                             final String username,
                                                             final String password) {
        return new SpnegoClient(provider.loginWithUsernamePassword(username, password));
    }

    /**
     * Creates an instance where authentication is done using an enterprise principal name and password.
     *
     * <p>Enterprise principal names are user principal names such as {@code user@example.com}. They are sent as
     * Kerberos {@code NT_ENTERPRISE} client names to the configured realm, not parsed as {@code user@REALM}.
     * This is currently supported by the Kerby provider.</p>
     *
     * @param enterprisePrincipal enterprise principal name, for example {@code dmitry.bedrin@db.com}
     * @param password password
     */
    public static SpnegoClient loginWithEnterprisePrincipal(final String enterprisePrincipal, final String password) {
        return loginWithEnterprisePrincipal(enterprisePrincipal, password, false);
    }

    /**
     * Creates an instance where authentication is done using an enterprise principal name and password.
     *
     * @param enterprisePrincipal enterprise principal name, for example {@code dmitry.bedrin@db.com}
     * @param password password
     * @param useCache if true, reuse a cached {@link SpnegoClient} for the same provider and credentials
     */
    public static SpnegoClient loginWithEnterprisePrincipal(final String enterprisePrincipal,
                                                           final String password,
                                                           final boolean useCache) {
        SpnegoClientProvider provider = SpnegoClientProviderRegistry.getPreferredProvider();
        if (!useCache) {
            return loginWithEnterprisePrincipalImpl(provider, enterprisePrincipal, password);
        }
        CacheKey entry = CacheKey.enterprisePrincipal(provider.getName(), enterprisePrincipal, password);
        SpnegoClient spnegoClient;
        synchronized (SPNEGO_CLIENT_CACHE) {
            spnegoClient = SPNEGO_CLIENT_CACHE.get(entry);
            if (null == spnegoClient) {
                spnegoClient = loginWithEnterprisePrincipalImpl(provider, enterprisePrincipal, password);
                SPNEGO_CLIENT_CACHE.put(entry, spnegoClient);
            }
        }
        return spnegoClient;
    }

    private static SpnegoClient loginWithEnterprisePrincipalImpl(SpnegoClientProvider provider,
                                                                final String enterprisePrincipal,
                                                                final String password) {
        return new SpnegoClient(provider.loginWithEnterprisePrincipal(enterprisePrincipal, password));
    }

    /**
     * Creates an instance where authentication is done using keytab file.
     *
     * @param principal      principal
     * @param keyTabLocation keyTabLocation
     */
    public static SpnegoClient loginWithKeyTab(final String principal, final String keyTabLocation) {
        return loginWithKeyTab(principal, keyTabLocation, false);
    }

    /**
     * Creates an instance where authentication is done using keytab file.
     * Allows customizing underlying isInitiator parameter by using acceptOnly parameter - see description below.
     *
     * @param principal      principal
     * @param keyTabLocation keyTabLocation
     * @param acceptOnly     when set to true, SpnegoClient will work offline and ONLY for accepting new tokens. As a result it doesn't require connection to Kerberos server but cannot request new tokens for other services
     * @since 0.1.3
     */
    public static SpnegoClient loginWithKeyTab(final String principal, final String keyTabLocation, final boolean acceptOnly) {
        return new SpnegoClient(SpnegoClientProviderRegistry.getPreferredProvider()
                .loginWithKeyTab(principal, keyTabLocation, acceptOnly));
    }

    /**
     * Creates an instance where authentication is done using ticket cache.
     *
     * @param principal principal
     */
    public static SpnegoClient loginWithTicketCache(final String principal) {
        return new SpnegoClient(SpnegoClientProviderRegistry.getPreferredProvider().loginWithTicketCache(principal));
    }

    public static SpnegoClient loginWithContext(final LoginContext loginContext) {
        return loginWithContextSupplier(() -> loginContext);
    }

    public static SpnegoClient loginWithContextSupplier(final Callable<LoginContext> loginContextSupplier) {
        return new SpnegoClient(new SubjectBasedSpnegoClientBackend(
                "jaas-login-context",
                JaasSubjectSupplier.fromLoginContextSupplier(loginContextSupplier)));
    }

    public String getImplementationName() {
        return backend.getImplementationName();
    }

    public Subject getSubject() {
        return backend.getSubject();
    }

    public KerberosKey[] getKerberosKeys() {
        return backend.getKerberosKeys();
    }

    public SpnegoContext createContext(URL url) throws PrivilegedActionException, GSSException {
        return backend.createContext(this, url);
    }

    public SpnegoContext createContextOrThrow(URL url) throws Kerb4JKerberosException {
        try {
            return createContext(url);
        } catch (PrivilegedActionException | GSSException e) {
            throw KerberosFailureAnalyzer.wrap("spnego.create-context", e);
        }
    }

    public SpnegoContext createContextForSPN(String spn) throws PrivilegedActionException, GSSException, MalformedURLException {
        return backend.createContextForSPN(this, spn);
    }

    public SpnegoContext createContextForSPNOrThrow(String spn) throws Kerb4JKerberosException {
        try {
            return createContextForSPN(spn);
        } catch (PrivilegedActionException | GSSException | MalformedURLException e) {
            throw KerberosFailureAnalyzer.wrap("spnego.create-context-for-spn", e);
        }
    }

    public String createAuthroizationHeader(URL url) throws PrivilegedActionException, GSSException, IOException {
        SpnegoContext context = createContext(url);
        try {
            return context.createTokenAsAuthroizationHeader();
        } finally {
            context.close();
        }
    }

    public String createAuthorizationHeader(URL url) throws Kerb4JKerberosException, IOException {
        SpnegoContext context = createContextOrThrow(url);
        try {
            return context.createTokenAsAuthorizationHeader();
        } finally {
            context.close();
        }
    }

    public String createAuthroizationHeaderForSPN(String spn) throws PrivilegedActionException, GSSException, IOException {
        SpnegoContext contextForSPN = createContextForSPN(spn);
        try {
            return contextForSPN.createTokenAsAuthroizationHeader();
        } finally {
            contextForSPN.close();
        }
    }

    public String createAuthorizationHeaderForSPN(String spn) throws Kerb4JKerberosException, IOException {
        SpnegoContext contextForSPN = createContextForSPNOrThrow(spn);
        try {
            return contextForSPN.createTokenAsAuthorizationHeader();
        } finally {
            contextForSPN.close();
        }
    }

    public SpnegoContext createAcceptContext() throws PrivilegedActionException {
        return backend.createAcceptContext(this);
    }

    public SpnegoContext createAcceptContextOrThrow() throws Kerb4JKerberosException {
        try {
            return createAcceptContext();
        } catch (PrivilegedActionException e) {
            throw KerberosFailureAnalyzer.wrap("spnego.create-accept-context", e);
        }
    }

    private static final class SpnegoClientProviderRegistry {

        private static final Logger LOGGER = LoggerFactory.getLogger(SpnegoClientProviderRegistry.class);
        private static final String KERBY_PROVIDER_CLASS = "com.kerb4j.client.kerby.KerbySpnegoClientProvider";
        private static final String JDK_PROVIDER_CLASS = "com.kerb4j.client.jdk.JdkSpnegoClientProvider";
        private static final String KERBY_PROVIDER_ALIAS = "kerby";
        private static final String JDK_PROVIDER_ALIAS = "jdk";

        private static volatile SpnegoClientProvider preferredProvider;

        private SpnegoClientProviderRegistry() {
        }

        private static void reset() {
            preferredProvider = null;
        }

        private static SpnegoClientProvider getPreferredProvider() {
            SpnegoClientProvider provider = preferredProvider;
            if (null != provider) {
                return provider;
            }
            synchronized (SpnegoClientProviderRegistry.class) {
                provider = preferredProvider;
                if (null == provider) {
                    String providerOverride = System.getProperty(SPNEGO_PROVIDER_PROPERTY);
                    if (providerOverride != null && !providerOverride.trim().isEmpty()) {
                        provider = loadRequiredProvider(toProviderClassName(providerOverride.trim()));
                    } else {
                        provider = loadProvider(KERBY_PROVIDER_CLASS);
                    }
                    if (null == provider) {
                        provider = loadProvider(JDK_PROVIDER_CLASS);
                    }
                    if (null == provider) {
                        throw new IllegalStateException("No Kerb4J SPNEGO client implementation is available. "
                                + "Add kerb4j-client-kerby or kerb4j-client-jdk to the runtime classpath.");
                    }
                    preferredProvider = provider;
                }
            }
            return provider;
        }

        private static String toProviderClassName(String providerOverride) {
            if (KERBY_PROVIDER_ALIAS.equalsIgnoreCase(providerOverride)) {
                return KERBY_PROVIDER_CLASS;
            }
            if (JDK_PROVIDER_ALIAS.equalsIgnoreCase(providerOverride)) {
                return JDK_PROVIDER_CLASS;
            }
            return providerOverride;
        }

        private static SpnegoClientProvider loadRequiredProvider(String className) {
            SpnegoClientProvider provider = loadProvider(className);
            if (provider == null) {
                throw new IllegalStateException("Configured Kerb4J SPNEGO client provider is not available: "
                        + className + ". Check " + SPNEGO_PROVIDER_PROPERTY + " and the runtime classpath.");
            }
            return provider;
        }

        private static SpnegoClientProvider loadProvider(String className) {
            ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            try {
                Class<?> providerClass = Class.forName(className, true,
                        contextClassLoader == null ? SpnegoClient.class.getClassLoader() : contextClassLoader);
                return (SpnegoClientProvider) providerClass.getDeclaredConstructor().newInstance();
            } catch (ClassNotFoundException e) {
                return null;
            } catch (ReflectiveOperationException | LinkageError e) {
                LOGGER.warn("Unable to load SPNEGO client provider {}", className, e);
                return null;
            }
        }
    }

    private static final class CacheKey extends AbstractMap.SimpleEntry<String, String> {
        private final String type;
        private final String provider;

        private CacheKey(String type, String provider, String key, String value) {
            super(key, value);
            this.type = type;
            this.provider = provider;
        }

        private static CacheKey usernamePassword(String provider, String username, String password) {
            return new CacheKey("username-password", provider, username, password);
        }

        private static CacheKey enterprisePrincipal(String provider, String enterprisePrincipal, String password) {
            return new CacheKey("enterprise-principal", provider, enterprisePrincipal, password);
        }

        @Override
        public boolean equals(Object obj) {
            return super.equals(obj) && obj instanceof CacheKey
                    && type.equals(((CacheKey) obj).type)
                    && provider.equals(((CacheKey) obj).provider);
        }

        @Override
        public int hashCode() {
            int result = type.hashCode();
            result = 31 * result + provider.hashCode();
            result = 31 * result + super.hashCode();
            return result;
        }
    }
}
