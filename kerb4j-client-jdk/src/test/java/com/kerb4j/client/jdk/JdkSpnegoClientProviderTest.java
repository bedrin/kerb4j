package com.kerb4j.client.jdk;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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

    @Test
    void singletonClientCreatesIndependentInitialTokensConcurrentlyWithoutReplayRejection() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "jdk-concurrent-server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "concurrent-client/localhost";
        File clientKeytab = new File(workDir, "jdk-concurrent-client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpnegoClient initiator = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());
        SpnegoClient acceptor = SpnegoClient.loginWithKeyTab(serverPrincipal, serverKeytab.getAbsolutePath(), true);
        int operationCount = 16;
        ExecutorService executor = Executors.newFixedThreadPool(operationCount);
        CountDownLatch contextsReady = new CountDownLatch(operationCount);
        CountDownLatch createTokens = new CountDownLatch(1);
        List<Future<ContextPair>> operations = new ArrayList<>();

        try {
            for (int i = 0; i < operationCount; i++) {
                operations.add(executor.submit(() -> {
                    try (SpnegoContext initiatorContext = initiator.createContextForSPN(serverPrincipal)) {
                        contextsReady.countDown();
                        if (!createTokens.await(30, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Timed out waiting to create initial tokens");
                        }
                        byte[] token = initiatorContext.createToken();
                        assertNotNull(token);
                        assertTrue(token.length > 0);

                        try (SpnegoContext acceptorContext = acceptor.createAcceptContext()) {
                            acceptorContext.acceptToken(token);
                            assertTrue(acceptorContext.isEstablished());
                            return new ContextPair(initiatorContext, acceptorContext);
                        }
                    }
                }));
            }

            assertTrue(contextsReady.await(30, TimeUnit.SECONDS));
            createTokens.countDown();

            List<ContextPair> contextPairs = new ArrayList<>();
            for (Future<ContextPair> operation : operations) {
                contextPairs.add(operation.get(30, TimeUnit.SECONDS));
            }
            assertIndependentContexts(contextPairs);
        } finally {
            createTokens.countDown();
            executor.shutdownNow();
        }
    }

    private static void assertIndependentContexts(List<ContextPair> contextPairs) {
        for (int i = 0; i < contextPairs.size(); i++) {
            for (int j = i + 1; j < contextPairs.size(); j++) {
                assertNotSame(contextPairs.get(i).initiatorContext(), contextPairs.get(j).initiatorContext());
                assertNotSame(contextPairs.get(i).initiatorContext().getGSSContext(),
                        contextPairs.get(j).initiatorContext().getGSSContext());
                assertNotSame(contextPairs.get(i).acceptorContext(), contextPairs.get(j).acceptorContext());
                assertNotSame(contextPairs.get(i).acceptorContext().getGSSContext(),
                        contextPairs.get(j).acceptorContext().getGSSContext());
            }
        }
    }

    private record ContextPair(SpnegoContext initiatorContext, SpnegoContext acceptorContext) {
    }
}
