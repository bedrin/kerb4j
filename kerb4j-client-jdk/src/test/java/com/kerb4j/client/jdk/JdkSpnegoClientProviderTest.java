package com.kerb4j.client.jdk;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class JdkSpnegoClientProviderTest extends KerberosSecurityTestcase {

    @AfterEach
    void resetProviderOverride() {
        System.clearProperty(SpnegoClient.SPNEGO_PROVIDER_PROPERTY);
        SpnegoClient.resetCache();
    }

    @Test
    void jdkProviderIsUsedWhenKerbyProviderIsNotOnClasspath() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "jdk-server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "client/localhost";
        File clientKeytab = new File(workDir, "jdk-client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpnegoClient initiator = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());
        SpnegoClient acceptor = SpnegoClient.loginWithKeyTab(serverPrincipal, serverKeytab.getAbsolutePath(), true);

        assertEquals(JdkSpnegoClientProvider.NAME, initiator.getImplementationName());
        byte[] token;
        try (SpnegoContext initiatorContext = initiator.createContextForSPN(serverPrincipal)) {
            token = initiatorContext.createToken();
        }

        assertNotNull(token);
        assertTrue(token.length > 0);
        try (SpnegoContext acceptContext = acceptor.createAcceptContext()) {
            acceptContext.acceptToken(token);
            assertTrue(acceptContext.isEstablished());
        }
    }

    @Test
    void jdkProviderDoesNotSupportEnterprisePrincipalLogin() {
        UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> SpnegoClient.loginWithEnterprisePrincipal("dmitry.bedrin@db.com", "password"));

        assertTrue(exception.getMessage().contains("Enterprise principal login"));
    }
}
