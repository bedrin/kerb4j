package com.kerb4j.client.kerby;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.jdk.JdkSpnegoClientProvider;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.security.PrivilegedActionException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KerbySpnegoClientProviderTest extends KerberosSecurityTestcase {

    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

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

    @Test
    void kerbyProviderConfiguresInitiatorAndAcceptOnlyModesExplicitly() throws Exception {
        KerbySpnegoClientProvider provider = new KerbySpnegoClientProvider();

        assertSubjectMode(provider.loginWithUsernamePassword("client", "password"), "INITIATOR");
        assertSubjectMode(provider.loginWithEnterprisePrincipal("user@example.com", "password"), "INITIATOR");
        assertSubjectMode(provider.loginWithKeyTab("client", "client.keytab", false), "INITIATOR");
        assertSubjectMode(provider.loginWithKeyTab("HTTP/service", "service.keytab", true), "ACCEPT_ONLY");
    }

    @Test
    void kerbyBackendRefreshesExactTgtAndRetriesNoCredContextConstructionOnce() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String serverPrincipal = "HTTP/localhost";
        File serverKeytab = new File(workDir, "kerby-retry-server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "retry-client";
        String clientPassword = "changeit";
        kdc.createPrincipal(clientPrincipal, clientPassword);

        AtomicInteger contextAttempts = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                KerbySpnegoClientProvider.KerbyCredentials.withPassword(clientPrincipal, clientPassword);
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend =
                new KerbySpnegoClientProvider.KerbySpnegoClientBackend(credentials) {
                    @Override
                    protected GSSContext getGSSContext(Subject subject, GSSName gssName)
                            throws GSSException, PrivilegedActionException {
                        if (contextAttempts.incrementAndGet() == 1) {
                            throw new PrivilegedActionException(new GSSException(GSSException.NO_CRED));
                        }
                        return super.getGSSContext(subject, gssName);
                    }
                };
        SpnegoClient acceptor = SpnegoClient.loginWithKeyTab(
                serverPrincipal, serverKeytab.getAbsolutePath(), true);

        byte[] token;
        try (SpnegoContext initiatorContext = backend.createContextForSPN(null, serverPrincipal)) {
            token = initiatorContext.createToken();
        }

        assertEquals(2, contextAttempts.get());
        try (SpnegoContext acceptContext = acceptor.createAcceptContext()) {
            acceptContext.acceptToken(token);
            assertTrue(acceptContext.isEstablished());
        }
    }

    @Test
    void credentialFailureDuringServiceTicketRequestRefreshesExactTgtAndRetriesOnce() throws Exception {
        TgtTicket failedTgt = tgt((byte) 1);
        TgtTicket refreshedTgt = tgt((byte) 2);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger serviceCalls = new AtomicInteger();
        Subject successfulSubject = new Subject();
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials(requesterCalls, failedTgt, refreshedTgt),
                (tgt, ignored) -> {
                    serviceCalls.incrementAndGet();
                    if (tgt == failedTgt) {
                        throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
                    }
                    return successfulSubject;
                },
                (subject, ignored) -> mock(GSSContext.class));

        try (SpnegoContext ignored = backend.createContextForSPN(null, "HTTP/localhost")) {
            assertEquals(2, requesterCalls.get());
            assertEquals(2, serviceCalls.get());
        }
    }

    @Test
    void permanentKerbyServiceTicketFailureIsNotRetried() {
        TgtTicket tgt = tgt((byte) 1);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger serviceCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials(requesterCalls, tgt),
                (ignoredTgt, ignoredSpn) -> {
                    serviceCalls.incrementAndGet();
                    throw new KrbException(KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);
                },
                (subject, ignored) -> mock(GSSContext.class));

        PrivilegedActionException failure = assertThrows(PrivilegedActionException.class,
                () -> backend.createContextForSPN(null, "HTTP/localhost"));

        assertEquals(KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
                ((KrbException) failure.getCause()).getKrbErrorCode());
        assertEquals(1, requesterCalls.get());
        assertEquals(1, serviceCalls.get());
    }

    @Test
    void twoKerbyCredentialFailuresStopAfterSecondAndSuppressFirst() {
        TgtTicket firstTgt = tgt((byte) 1);
        TgtTicket secondTgt = tgt((byte) 2);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger serviceCalls = new AtomicInteger();
        List<KrbException> causes = new ArrayList<>();
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials(requesterCalls, firstTgt, secondTgt),
                (ignoredTgt, ignoredSpn) -> {
                    serviceCalls.incrementAndGet();
                    KrbException failure = new KrbException(KrbErrorCode.KRB_AP_ERR_NO_TGT);
                    causes.add(failure);
                    throw failure;
                },
                (subject, ignored) -> mock(GSSContext.class));

        PrivilegedActionException failure = assertThrows(PrivilegedActionException.class,
                () -> backend.createContextForSPN(null, "HTTP/localhost"));

        assertSame(causes.get(1), failure.getCause());
        assertEquals(1, failure.getSuppressed().length);
        assertSame(causes.get(0), failure.getSuppressed()[0].getCause());
        assertEquals(2, requesterCalls.get());
        assertEquals(2, serviceCalls.get());
    }

    @Test
    void staleKerbyServiceFailureCannotInvalidateNewerTgt() throws Exception {
        TgtTicket staleTgt = tgt((byte) 1);
        TgtTicket freshTgt = tgt((byte) 2);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger staleServiceCalls = new AtomicInteger();
        CountDownLatch staleAttemptStarted = new CountDownLatch(1);
        CountDownLatch allowStaleFailure = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials(requesterCalls, staleTgt, freshTgt),
                (tgt, ignored) -> {
                    if (tgt == staleTgt) {
                        if (staleServiceCalls.incrementAndGet() == 1) {
                            staleAttemptStarted.countDown();
                            if (!allowStaleFailure.await(10, TimeUnit.SECONDS)) {
                                throw new IllegalStateException("Timed out waiting to release stale failure");
                            }
                        }
                        throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
                    }
                    return new Subject();
                },
                (subject, ignored) -> mock(GSSContext.class));

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<SpnegoContext> staleResult = executor.submit(
                    () -> backend.createContextForSPN(null, "HTTP/localhost"));
            assertTrue(staleAttemptStarted.await(10, TimeUnit.SECONDS));

            try (SpnegoContext ignored = backend.createContextForSPN(null, "HTTP/localhost")) {
                allowStaleFailure.countDown();
                try (SpnegoContext staleContext = staleResult.get(10, TimeUnit.SECONDS)) {
                    assertNotNull(staleContext);
                }
            }
        } finally {
            allowStaleFailure.countDown();
            executor.shutdownNow();
        }

        assertEquals(2, requesterCalls.get());
        assertEquals(2, staleServiceCalls.get());
    }

    @Test
    void kerbyTokenGenerationNoCredIsNotRetried() throws Exception {
        TgtTicket tgt = tgt((byte) 1);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger serviceCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        AtomicInteger tokenCalls = new AtomicInteger();
        GSSContext tokenFailureContext = (GSSContext) Proxy.newProxyInstance(
                GSSContext.class.getClassLoader(), new Class[]{GSSContext.class}, (proxy, method, args) -> {
                    if ("initSecContext".equals(method.getName())) {
                        tokenCalls.incrementAndGet();
                        throw new GSSException(GSSException.NO_CRED);
                    }
                    return defaultValue(method.getReturnType());
                });
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials(requesterCalls, tgt),
                (ignoredTgt, ignoredSpn) -> {
                    serviceCalls.incrementAndGet();
                    return new Subject();
                },
                (subject, ignored) -> {
                    contextCalls.incrementAndGet();
                    return tokenFailureContext;
                });

        try (SpnegoContext context = backend.createContextForSPN(null, "HTTP/localhost")) {
            PrivilegedActionException failure = assertThrows(PrivilegedActionException.class, context::createToken);
            assertEquals(GSSException.NO_CRED, ((GSSException) failure.getCause()).getMajor());
        }

        assertEquals(1, requesterCalls.get());
        assertEquals(1, serviceCalls.get());
        assertEquals(1, contextCalls.get());
        assertEquals(1, tokenCalls.get());
    }

    @Test
    void kerbyNoCredInvalidationBypassesAdaptiveRetryTime() throws Exception {
        TgtTicket nearExpiryTgt = tgt((byte) 1, NOW.plusSeconds(30));
        TgtTicket refreshedTgt = tgt((byte) 2);
        AtomicInteger requesterCalls = new AtomicInteger();
        AtomicInteger serviceCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                new KerbySpnegoClientProvider.KerbyCredentials(() ->
                        requesterCalls.incrementAndGet() < 3 ? nearExpiryTgt : refreshedTgt, CLOCK);

        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        KerbySpnegoClientProvider.KerbySpnegoClientBackend backend = backend(
                credentials,
                (ignoredTgt, ignoredSpn) -> {
                    serviceCalls.incrementAndGet();
                    return new Subject();
                },
                (subject, ignored) -> {
                    if (contextCalls.incrementAndGet() == 1) {
                        throw new PrivilegedActionException(new GSSException(GSSException.NO_CRED));
                    }
                    return mock(GSSContext.class);
                });

        try (SpnegoContext ignored = backend.createContextForSPN(null, "HTTP/localhost")) {
            assertEquals(3, requesterCalls.get());
            assertEquals(2, serviceCalls.get());
            assertEquals(2, contextCalls.get());
        }
    }

    private static void assertSubjectMode(SpnegoClientBackend backend, String expectedMode) throws Exception {
        Field subjectMode = SubjectBasedSpnegoClientBackend.class.getDeclaredField("subjectMode");
        subjectMode.setAccessible(true);
        assertEquals(expectedMode, subjectMode.get(backend).toString());
    }

    private static KerbySpnegoClientProvider.KerbyCredentials credentials(AtomicInteger calls,
                                                                           TgtTicket... tickets) {
        return new KerbySpnegoClientProvider.KerbyCredentials(
                () -> tickets[Math.min(calls.getAndIncrement(), tickets.length - 1)], CLOCK);
    }

    private static KerbySpnegoClientProvider.KerbySpnegoClientBackend backend(
            KerbySpnegoClientProvider.KerbyCredentials credentials,
            ServiceSubjectFactory serviceSubjectFactory, ContextFactory contextFactory) {
        return new KerbySpnegoClientProvider.KerbySpnegoClientBackend(credentials) {
            @Override
            protected Subject getServiceSubject(TgtTicket tgt, String servicePrincipal) throws Exception {
                return serviceSubjectFactory.create(tgt, servicePrincipal);
            }

            @Override
            protected GSSContext getGSSContext(Subject subject, GSSName gssName)
                    throws GSSException, PrivilegedActionException {
                return contextFactory.create(subject, gssName);
            }
        };
    }

    private static TgtTicket tgt(byte id) {
        return tgt(id, NOW.plusSeconds(600));
    }

    private static TgtTicket tgt(byte id, Instant endTime) {
        EncKdcRepPart part = mock(EncKdcRepPart.class);
        when(part.getEndTime()).thenReturn(new KerberosTime(endTime.toEpochMilli()));
        TgtTicket tgt = mock(TgtTicket.class, "tgt-" + id);
        when(tgt.getEncKdcRepPart()).thenReturn(part);
        return tgt;
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive() || Void.TYPE.equals(type)) {
            return null;
        }
        if (Boolean.TYPE.equals(type)) {
            return false;
        }
        if (Character.TYPE.equals(type)) {
            return '\0';
        }
        return 0;
    }

    @FunctionalInterface
    private interface ServiceSubjectFactory {
        Subject create(TgtTicket tgt, String servicePrincipal) throws Exception;
    }

    @FunctionalInterface
    private interface ContextFactory {
        GSSContext create(Subject subject, GSSName gssName) throws GSSException, PrivilegedActionException;
    }
}
