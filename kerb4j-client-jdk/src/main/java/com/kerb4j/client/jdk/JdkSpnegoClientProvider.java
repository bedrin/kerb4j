package com.kerb4j.client.jdk;

import com.kerb4j.client.spi.JaasSubjectSupplier;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.jaas.sun.Krb5LoginContext;

import javax.security.auth.Subject;
import java.util.concurrent.Callable;

public class JdkSpnegoClientProvider implements SpnegoClientProvider {

    public static final String NAME = "jdk-jgss";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public SpnegoClientBackend loginWithUsernamePassword(String username, String password) {
        return new JdkSubjectBasedSpnegoClientBackend(
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithUsernameAndPassword(username, password)), false);
    }

    @Override
    public SpnegoClientBackend loginWithEnterprisePrincipal(String enterprisePrincipal, String password) {
        throw new UnsupportedOperationException("Enterprise principal login is not supported by the JDK SPNEGO provider");
    }

    @Override
    public SpnegoClientBackend loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
        return new JdkSubjectBasedSpnegoClientBackend(
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation, acceptOnly)), acceptOnly);
    }

    @Override
    public SpnegoClientBackend loginWithTicketCache(String principal) {
        return new JdkSubjectBasedSpnegoClientBackend(
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithTicketCache(principal)), false);
    }

    // Bridges the provider to the internal mode-aware constructor without changing the public API.
    private static class JdkSubjectBasedSpnegoClientBackend extends SubjectBasedSpnegoClientBackend {

        private JdkSubjectBasedSpnegoClientBackend(Callable<Subject> subjectSupplier, boolean acceptOnly) {
            super(NAME, subjectSupplier, acceptOnly);
        }
    }
}
