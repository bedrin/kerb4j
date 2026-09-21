package com.kerb4j.common.exception;

import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.Test;

import javax.security.auth.login.LoginException;
import java.security.PrivilegedActionException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

class KerberosFailureAnalyzerTest {

    @Test
    void classifiesClockSkewFromLoginException() {
        Kerb4JKerberosException exception = KerberosFailureAnalyzer.wrap(
                "kerberos.login",
                new LoginException("Clock skew too great"));

        assertThat(exception, instanceOf(KerberosClockSkewException.class));
        assertEquals(KerberosFailureCode.CLOCK_SKEW_TOO_LARGE, exception.getFailureCode());
        assertThat(exception.getMessage(), containsString("Synchronize"));
        assertThat(exception.getMessage(), containsString("javax.security.auth.login.LoginException"));
    }

    @Test
    void classifiesServerPrincipalProblemsFromGssException() {
        GSSException gssException = new GSSException(GSSException.FAILURE);
        gssException.initCause(new RuntimeException("Server not found in Kerberos database"));

        Kerb4JKerberosException exception = KerberosFailureAnalyzer.wrap("spnego.create-context", gssException);

        assertThat(exception, instanceOf(KerberosServicePrincipalException.class));
        assertEquals(KerberosFailureCode.SERVER_PRINCIPAL_NOT_FOUND, exception.getFailureCode());
        assertThat(exception.getMessage(), containsString("SPN"));
    }

    @Test
    void unwrapsPrivilegedActionExceptionForClassification() {
        PrivilegedActionException privilegedActionException = new PrivilegedActionException(
                new LoginException("Cannot find key of appropriate type to decrypt AP-REQ"));

        Kerb4JKerberosException exception = KerberosFailureAnalyzer.wrap("spnego.accept-token", privilegedActionException);

        assertThat(exception, instanceOf(KerberosEncryptionException.class));
        assertEquals(KerberosFailureCode.UNSUPPORTED_ENCRYPTION_TYPE, exception.getFailureCode());
        assertEquals(privilegedActionException, exception.getCause());
    }
}
