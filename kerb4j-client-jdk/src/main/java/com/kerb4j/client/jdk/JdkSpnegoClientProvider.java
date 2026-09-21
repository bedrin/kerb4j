package com.kerb4j.client.jdk;

import com.kerb4j.client.spi.JaasSubjectSupplier;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.exception.KerberosFailureAnalyzer;
import com.kerb4j.common.exception.KerberosFailureCategory;
import com.kerb4j.common.exception.KerberosFailureCode;
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
    public SpnegoClientBackend loginWithEnterprisePrincipal(String enterprisePrincipal, String password) {
        throw KerberosFailureAnalyzer.explicit(
                "kerberos.login-with-enterprise-principal",
                KerberosFailureCode.UNSUPPORTED_OPERATION,
                KerberosFailureCategory.PROVIDER,
                "Enterprise principal login is not supported by the JDK SPNEGO provider.",
                null,
                "The JDK provider cannot send the client name as Kerberos NT_ENTERPRISE",
                "Use the apache-kerby provider for enterprise principal login");
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
