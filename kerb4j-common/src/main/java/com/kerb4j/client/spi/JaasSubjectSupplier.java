package com.kerb4j.client.spi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.concurrent.Callable;

public final class JaasSubjectSupplier {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaasSubjectSupplier.class);

    private JaasSubjectSupplier() {
    }

    public static Callable<Subject> fromLoginContextSupplier(final Callable<LoginContext> loginContextSupplier) {
        return () -> {
            LoginContext loginContext = loginContextSupplier.call();
            Subject subject = loginContext.getSubject();
            if (null == subject) {
                try {
                    loginContext.login();
                    subject = loginContext.getSubject();
                } catch (LoginException e) {
                    LOGGER.error(e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            }
            return subject;
        };
    }
}
