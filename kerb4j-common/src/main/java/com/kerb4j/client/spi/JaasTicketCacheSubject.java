package com.kerb4j.client.spi;

import com.kerb4j.common.util.JreVendor;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class JaasTicketCacheSubject {

    private JaasTicketCacheSubject() {
    }

    public static Subject login(String principal, File credentialCache) throws LoginException {
        Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));
        Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());
        LoginContext loginContext = new LoginContext("Kerb4JTicketCache", subject, null,
                new TicketCacheConfiguration(principal, credentialCache));
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Subject loginWithPassword(String principal, CallbackHandler callbackHandler) throws LoginException {
        Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));
        Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());
        LoginContext loginContext = new LoginContext("Kerb4JPassword", subject, callbackHandler,
                new PasswordConfiguration(principal));
        loginContext.login();
        return loginContext.getSubject();
    }

    private static String getKrb5LoginModuleName() {
        return JreVendor.IS_IBM_JVM
                ? "com.ibm.security.auth.module.Krb5LoginModule"
                : "com.sun.security.auth.module.Krb5LoginModule";
    }

    private static class TicketCacheConfiguration extends Configuration {
        private final String principal;
        private final File credentialCache;

        private TicketCacheConfiguration(String principal, File credentialCache) {
            this.principal = principal;
            this.credentialCache = credentialCache;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            options.put("useTicketCache", "true");
            options.put("ticketCache", credentialCache.getAbsolutePath());
            options.put("renewTGT", "true");
            options.put("doNotPrompt", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            if (Boolean.getBoolean("sun.security.krb5.debug")) {
                options.put("debug", "true");
            }
            return new AppConfigurationEntry[]{new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
        }
    }

    private static class PasswordConfiguration extends Configuration {
        private final String principal;

        private PasswordConfiguration(String principal) {
            this.principal = principal;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            options.put("storeKey", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            if (Boolean.getBoolean("sun.security.krb5.debug")) {
                options.put("debug", "true");
            }
            return new AppConfigurationEntry[]{new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
        }
    }
}
