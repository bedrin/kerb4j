package com.kerb4j.common.jaas.sun;

import com.kerb4j.common.util.SpnegoProvider;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class Krb5LoginContext extends LoginContext {

    private final static String UNUSED_CONFIGURATION_NAME = "";

    private Krb5LoginContext(String name, Subject subject, CallbackHandler callbackHandler, Configuration config) throws LoginException {
        super(name, subject, callbackHandler, config);
    }

    public static Krb5LoginContext loginWithKeyTab(String principal, String keyTabLocation) {
        try {
            Krb5LoginContext krb5LoginContext = new Krb5LoginContext(UNUSED_CONFIGURATION_NAME, null, null,
                    Krb5LoginConfig.createKeyTabClientConfig(principal, keyTabLocation)
            );
            krb5LoginContext.login();
            return krb5LoginContext;
        } catch (LoginException e) {
            // TODO: here and in other places consider throwing LoginException instead of RuntimeException(LoginException)
            throw new RuntimeException(e);
        }
    }

    public static Krb5LoginContext loginWithTicketCache(String principal) {
        try {
            Krb5LoginContext krb5LoginContext = new Krb5LoginContext(UNUSED_CONFIGURATION_NAME, null, null,
                    Krb5LoginConfig.createTicketCacheClientConfig(principal)
            );
            krb5LoginContext.login();
            return krb5LoginContext;
        } catch (LoginException e) {
            throw new RuntimeException(e);
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
            throw new RuntimeException(e);
        }
    }

}
