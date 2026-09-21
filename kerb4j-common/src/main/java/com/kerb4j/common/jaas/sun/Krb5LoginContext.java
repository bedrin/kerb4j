package com.kerb4j.common.jaas.sun;

import com.kerb4j.common.exception.KerberosFailureAnalyzer;
import com.kerb4j.common.util.SpnegoProvider;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.Collections;

/**
 * JDK JAAS login context helper.
 * <p>
 * JDK JAAS support is implemented by the {@code kerb4j-client-jdk} provider module. This compatibility type remains
 * in {@code kerb4j-common} for existing callers that configure the JDK provider directly.
 */
@Deprecated
public class Krb5LoginContext extends LoginContext {

    private final static String UNUSED_CONFIGURATION_NAME = "";

    private Krb5LoginContext(String name, Subject subject, CallbackHandler callbackHandler, Configuration config) throws LoginException {
        super(name, subject, callbackHandler, config);
    }

    /**
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     * @param acceptOnly when set to true, SpnegoClient will work offline and ONLY for accepting new tokens. As a result it doesn't require connection to Kerberos server but cannot request new tokens for other services
     * @since 0.1.3
     */
    public static Krb5LoginContext loginWithKeyTab(String principal, String keyTabLocation, final boolean acceptOnly) {
        try {
            Krb5LoginContext krb5LoginContext = new Krb5LoginContext(UNUSED_CONFIGURATION_NAME, null, null,
                    Krb5LoginConfig.createKeyTabClientConfig(principal, keyTabLocation, Collections.singletonMap("isInitiator", acceptOnly ? "false" : "true"))
            );
            krb5LoginContext.login();
            return krb5LoginContext;
        } catch (LoginException e) {
            throw KerberosFailureAnalyzer.wrap("kerberos.login-with-keytab", e);
        }
    }

    public static Krb5LoginContext loginWithKeyTab(String principal, String keyTabLocation) {
        return loginWithKeyTab(principal, keyTabLocation, false);
    }

    public static Krb5LoginContext loginWithTicketCache(String principal) {
        try {
            Krb5LoginContext krb5LoginContext = new Krb5LoginContext(UNUSED_CONFIGURATION_NAME, null, null,
                    Krb5LoginConfig.createTicketCacheClientConfig(principal)
            );
            krb5LoginContext.login();
            return krb5LoginContext;
        } catch (LoginException e) {
            throw KerberosFailureAnalyzer.wrap("kerberos.login-with-ticket-cache", e);
        }
    }

    public static Krb5LoginContext loginWithUsernameAndPassword(String username, String password) {
        try {
            Krb5LoginContext krb5LoginContext = new Krb5LoginContext(UNUSED_CONFIGURATION_NAME, null,
                    SpnegoProvider.getUsernameAndPasswordHandler(username, password),
                    Krb5LoginConfig.createUsernameAndPasswordClientConfig()
            );
            krb5LoginContext.login();
            return krb5LoginContext;
        } catch (LoginException e) {
            throw KerberosFailureAnalyzer.wrap("kerberos.login-with-password", e);
        }
    }

}
