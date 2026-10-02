package com.kerb4j.client.kerby;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.jdk.JdkSpnegoClientProvider;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;

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
    void kerbyProviderBuildsTokensWithEnterprisePrincipalInitiator() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "kerby-enterprise-server.keytab");
        kdc.createPrincipal(serverPrincipal, "server-password");
        kdc.exportPrincipal(serverPrincipal, serverKeytab);

        String enterprisePrincipal = "dmitry.bedrin@db.com";
        String clientPassword = "client-password";
        String realm = kdc.getKdcSetting().getKdcRealm();
        PrincipalName clientPrincipal = new PrincipalName(
                Collections.singletonList(enterprisePrincipal),
                NameType.NT_ENTERPRISE);
        clientPrincipal.setRealm(realm);
        KrbIdentity clientIdentity = new KrbIdentity(clientPrincipal);
        clientIdentity.addKeys(EncryptionUtil.generateKeys(
                clientPrincipal.getName(),
                clientPassword,
                kdc.getKdcConfig().getEncryptionTypes()));
        kdc.getIdentityService().addIdentity(clientIdentity);

        SpnegoClient initiator = SpnegoClient.loginWithEnterprisePrincipal(enterprisePrincipal, clientPassword);
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
