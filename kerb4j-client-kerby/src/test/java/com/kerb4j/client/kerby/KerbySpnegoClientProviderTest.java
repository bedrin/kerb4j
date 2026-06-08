package com.kerb4j.client.kerby;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.jdk.JdkSpnegoClientProvider;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class KerbySpnegoClientProviderTest extends KerberosSecurityTestcase {

    @AfterEach
    void resetProviderOverride() {
        System.clearProperty(SpnegoClient.SPNEGO_PROVIDER_PROPERTY);
        SpnegoClient.resetCache();
    }

    @Test
    void kerbyProviderIsPreferredAndBuildsTokensWithKerbyTickets() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "kerby-server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "client";
        String clientPassword = "changeit";
        kdc.createPrincipal(clientPrincipal, clientPassword);

        SpnegoClient initiator = SpnegoClient.loginWithUsernamePassword(clientPrincipal, clientPassword);
        SpnegoClient acceptor = SpnegoClient.loginWithKeyTab(serverPrincipal, serverKeytab.getAbsolutePath(), true);

        assertEquals(KerbySpnegoClientProvider.NAME, initiator.getImplementationName());
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
    void kerbyProviderBuildsTokensWithKeytabInitiator() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "kerby-keytab-server.keytab");
        kdc.createPrincipal(serverPrincipal, "server-password");
        kdc.exportPrincipal(serverPrincipal, serverKeytab);

        String clientPrincipal = "client";
        File clientKeytab = new File(workDir, "kerby-client.keytab");
        kdc.createPrincipal(clientPrincipal, "client-password");
        kdc.exportPrincipal(clientPrincipal, clientKeytab);

        SpnegoClient initiator = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());
        SpnegoClient acceptor = SpnegoClient.loginWithKeyTab(serverPrincipal, serverKeytab.getAbsolutePath(), true);

        assertEquals(KerbySpnegoClientProvider.NAME, initiator.getImplementationName());
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
    void explicitOverrideCanForceJdkProviderWhenKerbyProviderIsPresent() {
        System.setProperty(SpnegoClient.SPNEGO_PROVIDER_PROPERTY, "jdk");
        SpnegoClient.resetCache();

        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab("unused", "unused.keytab");

        assertEquals(JdkSpnegoClientProvider.NAME, spnegoClient.getImplementationName());
    }
}
