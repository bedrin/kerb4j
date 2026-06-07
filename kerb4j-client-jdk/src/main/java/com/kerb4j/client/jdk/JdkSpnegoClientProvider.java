package com.kerb4j.client.jdk;

import com.kerb4j.client.spi.JaasSubjectSupplier;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.jaas.sun.Krb5LoginContext;

public class JdkSpnegoClientProvider implements SpnegoClientProvider {

    public static final String NAME = "jdk-jgss";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public SpnegoClientBackend loginWithUsernamePassword(String username, String password) {
        return new SubjectBasedSpnegoClientBackend(NAME,
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithUsernameAndPassword(username, password)));
    }

    @Override
    public SpnegoClientBackend loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
        return new SubjectBasedSpnegoClientBackend(NAME,
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation, acceptOnly)));
    }

    @Override
    public SpnegoClientBackend loginWithTicketCache(String principal) {
        return new SubjectBasedSpnegoClientBackend(NAME,
                JaasSubjectSupplier.fromLoginContextSupplier(
                        () -> Krb5LoginContext.loginWithTicketCache(principal)));
    }
}
