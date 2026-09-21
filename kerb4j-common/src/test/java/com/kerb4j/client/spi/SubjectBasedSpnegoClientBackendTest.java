package com.kerb4j.client.spi;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SubjectBasedSpnegoClientBackendTest {

    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void reusesTgtOutsideDefaultRefreshMargin() {
        Subject subject = subjectWithTgt(NOW.plusSeconds(61));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return subject;
        });

        assertSame(subject, backend.getSubject());
        assertSame(subject, backend.getSubject());

        assertEquals(1, supplierCalls.get());
    }

    @Test
    void refreshesTgtInsideDefaultRefreshMargin() {
        assertRefreshesAt(NOW.plusSeconds(59));
    }

    @Test
    void refreshesTgtExactlyAtDefaultRefreshMargin() {
        assertRefreshesAt(NOW.plusSeconds(60));
    }

    @Test
    void refreshesDestroyedTgtWithoutReadingItsEndTime() {
        KerberosTicket destroyedTgt = tgt(NOW.plusSeconds(600));
        when(destroyedTgt.isDestroyed()).thenReturn(true);
        Subject initialSubject = subjectWithTgt(destroyedTgt);
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        SubjectBasedSpnegoClientBackend backend = backend(sequence(initialSubject, refreshedSubject));

        assertSame(initialSubject, backend.getSubject());
        assertSame(refreshedSubject, backend.getSubject());

        verify(destroyedTgt, never()).getEndTime();
    }

    @Test
    void refreshesTgtWithNullEndTimeWithoutNullPointerException() {
        Subject initialSubject = subjectWithTgt((Instant) null);
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        SubjectBasedSpnegoClientBackend backend = backend(sequence(initialSubject, refreshedSubject));

        assertSame(initialSubject, backend.getSubject());
        assertSame(refreshedSubject, backend.getSubject());
    }

    @Test
    void concurrentCallersTriggerOneRefreshAndAllReceiveRefreshedSubject() throws Exception {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch allowRefresh = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            if (supplierCalls.incrementAndGet() == 1) {
                return initialSubject;
            }
            refreshStarted.countDown();
            if (!allowRefresh.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to complete refresh");
            }
            return refreshedSubject;
        });
        assertSame(initialSubject, backend.getSubject());

        int callerCount = 32;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Subject>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return backend.getSubject();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(refreshStarted.await(10, TimeUnit.SECONDS));
            allowRefresh.countDown();

            for (Future<Subject> result : results) {
                assertSame(refreshedSubject, result.get(10, TimeUnit.SECONDS));
            }
        } finally {
            allowRefresh.countDown();
            executor.shutdownNow();
        }

        assertEquals(2, supplierCalls.get());
    }

    @Test
    void supplierFailureDoesNotPublishReplacementState() {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return initialSubject;
            }
            if (call == 2) {
                throw new Exception("refresh failed");
            }
            return refreshedSubject;
        });
        assertSame(initialSubject, backend.getSubject());

        RuntimeException failure = assertThrows(RuntimeException.class, backend::getSubject);
        assertEquals("refresh failed", failure.getCause().getMessage());
        assertSame(refreshedSubject, backend.getSubject());
        assertSame(refreshedSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void initialExplicitAcceptOnlySubjectIsCachedAsEternal() {
        Subject acceptOnlySubject = new Subject();
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return acceptOnlySubject;
        }, true);

        assertSame(acceptOnlySubject, backend.getSubject());
        assertSame(acceptOnlySubject, backend.getSubject());

        assertEquals(1, supplierCalls.get());
    }

    @Test
    void initialInitiatorSubjectWithoutTgtFailsClearlyAndRemainsRetryable() {
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return new Subject();
        }, false);

        IllegalStateException firstFailure = assertThrows(IllegalStateException.class, backend::getSubject);
        IllegalStateException secondFailure = assertThrows(IllegalStateException.class, backend::getSubject);

        assertTrue(firstFailure.getMessage().contains("contains no Kerberos TGT"));
        assertTrue(secondFailure.getMessage().contains("contains no Kerberos TGT"));
        assertEquals(2, supplierCalls.get());
    }

    @Test
    void noTgtRefreshNeverReturnsExpiredSubjectAndLaterValidResultRecovers() {
        Subject expiredSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject invalidRefreshedSubject = new Subject();
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{expiredSubject, invalidRefreshedSubject, recoveredSubject}, supplierCalls));
        assertSame(expiredSubject, backend.getSubject());

        IllegalStateException failure = assertThrows(IllegalStateException.class, backend::getSubject);

        assertTrue(failure.getMessage().contains("contains no Kerberos TGT"));
        assertSame(recoveredSubject, backend.getSubject());
        assertSame(recoveredSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void concurrentCallersCannotObserveOldOrPartiallyPublishedStateAfterInvalidRefresh() throws Exception {
        Subject expiredSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject invalidRefreshedSubject = new Subject();
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch invalidRefreshStarted = new CountDownLatch(1);
        CountDownLatch allowInvalidRefresh = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return expiredSubject;
            }
            if (call == 2) {
                invalidRefreshStarted.countDown();
                if (!allowInvalidRefresh.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to complete invalid refresh");
                }
                return invalidRefreshedSubject;
            }
            return recoveredSubject;
        }, false);
        assertSame(expiredSubject, backend.getSubject());

        int callerCount = 16;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Subject>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return backend.getSubject();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(invalidRefreshStarted.await(10, TimeUnit.SECONDS));
            allowInvalidRefresh.countDown();

            int invalidRefreshFailures = 0;
            for (Future<Subject> result : results) {
                try {
                    assertSame(recoveredSubject, result.get(10, TimeUnit.SECONDS));
                } catch (ExecutionException e) {
                    assertTrue(e.getCause() instanceof IllegalStateException);
                    assertTrue(e.getCause().getMessage().contains("contains no Kerberos TGT"));
                    invalidRefreshFailures++;
                }
            }
            assertEquals(1, invalidRefreshFailures);
        } finally {
            allowInvalidRefresh.countDown();
            executor.shutdownNow();
        }

        assertSame(recoveredSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void retriesNoCredOnceAndCapturesSubjectFromSuccessfulAttempt() throws Exception {
        Subject failedSubject = subjectWithTgt(NOW.plusSeconds(600));
        Subject successfulSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        AtomicReference<Subject> tokenSubject = new AtomicReference<>();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{failedSubject, successfulSubject}, supplierCalls),
                (subject, ignored) -> {
                    if (contextCalls.incrementAndGet() == 1) {
                        throw new PrivilegedActionException(gssException(GSSException.NO_CRED));
                    }
                    return tokenContext(tokenSubject, null);
                });

        SpnegoContext context = createInitiatorContext(backend);
        context.createToken();

        assertEquals(2, supplierCalls.get());
        assertEquals(2, contextCalls.get());
        assertSame(successfulSubject, tokenSubject.get());
    }

    @Test
    void doesNotRetryNonNoCredFailure() {
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return subjectWithTgt(NOW.plusSeconds(600));
        }, (subject, ignored) -> {
            contextCalls.incrementAndGet();
            throw gssException(GSSException.BAD_NAME);
        });

        GSSException failure = assertThrows(GSSException.class,
                () -> createInitiatorContext(backend));

        assertEquals(GSSException.BAD_NAME, failure.getMajor());
        assertEquals(1, supplierCalls.get());
        assertEquals(1, contextCalls.get());
    }

    @Test
    void retriesNoCredNoMoreThanOnceAndSuppressesFirstFailure() {
        Subject firstSubject = subjectWithTgt(NOW.plusSeconds(600));
        Subject secondSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        List<PrivilegedActionException> failures = new java.util.ArrayList<>();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{firstSubject, secondSubject}, supplierCalls),
                (subject, ignored) -> {
                    contextCalls.incrementAndGet();
                    PrivilegedActionException failure =
                            new PrivilegedActionException(gssException(GSSException.NO_CRED));
                    failures.add(failure);
                    throw failure;
                });

        PrivilegedActionException failure = assertThrows(PrivilegedActionException.class,
                () -> createInitiatorContext(backend));

        assertEquals(2, supplierCalls.get());
        assertEquals(2, contextCalls.get());
        assertSame(failures.get(1), failure);
        assertEquals(1, failure.getSuppressed().length);
        assertSame(failures.get(0), failure.getSuppressed()[0]);
    }

    @Test
    void staleNoCredFailureDoesNotInvalidateConcurrentlyPublishedSubject() throws Exception {
        Subject staleSubject = subjectWithTgt(NOW.plusSeconds(600));
        Subject freshSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger staleContextCalls = new AtomicInteger();
        CountDownLatch staleAttemptStarted = new CountDownLatch(1);
        CountDownLatch allowStaleFailure = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{staleSubject, freshSubject}, supplierCalls),
                (subject, ignored) -> {
                    if (subject == staleSubject) {
                        if (staleContextCalls.incrementAndGet() == 1) {
                            staleAttemptStarted.countDown();
                            try {
                                if (!allowStaleFailure.await(10, TimeUnit.SECONDS)) {
                                    throw new IllegalStateException("Timed out waiting to release stale failure");
                                }
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new PrivilegedActionException(e);
                            }
                        }
                        throw new PrivilegedActionException(gssException(GSSException.NO_CRED));
                    }
                    return tokenContext(new AtomicReference<>(), null);
                });
        assertSame(staleSubject, backend.getSubject());

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<SpnegoContext> staleResult = executor.submit(
                    () -> createInitiatorContext(backend));
            assertTrue(staleAttemptStarted.await(10, TimeUnit.SECONDS));

            SpnegoContext concurrentResult =
                    createInitiatorContext(backend);
            allowStaleFailure.countDown();

            assertSame(freshSubject, backend.getSubject());
            assertNotSame(concurrentResult, staleResult.get(10, TimeUnit.SECONDS));
        } finally {
            allowStaleFailure.countDown();
            executor.shutdownNow();
        }

        assertEquals(2, supplierCalls.get());
        assertEquals(2, staleContextCalls.get());
    }

    @Test
    void doesNotRetryNoCredFromTokenGeneration() throws Exception {
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        AtomicInteger tokenCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return subjectWithTgt(NOW.plusSeconds(600));
        }, (subject, ignored) -> {
            contextCalls.incrementAndGet();
            return tokenContext(new AtomicReference<>(), tokenCalls);
        });

        SpnegoContext context = createInitiatorContext(backend);
        PrivilegedActionException failure = assertThrows(PrivilegedActionException.class, context::createToken);

        assertTrue(failure.getCause() instanceof GSSException);
        assertEquals(GSSException.NO_CRED, ((GSSException) failure.getCause()).getMajor());
        assertEquals(1, supplierCalls.get());
        assertEquals(1, contextCalls.get());
        assertEquals(1, tokenCalls.get());
    }

    private static void assertRefreshesAt(Instant endTime) {
        Subject initialSubject = subjectWithTgt(endTime);
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        Callable<Subject> supplier = sequence(new Subject[]{initialSubject, refreshedSubject}, supplierCalls);
        SubjectBasedSpnegoClientBackend backend = backend(supplier);

        assertSame(initialSubject, backend.getSubject());
        assertSame(refreshedSubject, backend.getSubject());
        assertSame(refreshedSubject, backend.getSubject());

        assertEquals(2, supplierCalls.get());
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, CLOCK);
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier, boolean acceptOnly) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, CLOCK, acceptOnly);
    }

    private static SpnegoContext createInitiatorContext(SubjectBasedSpnegoClientBackend backend)
            throws PrivilegedActionException, GSSException {
        return backend.createInitiatorContext(null, mock(GSSName.class));
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier,
                                                            ContextFactory contextFactory) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, CLOCK) {
            @Override
            protected GSSContext getGSSContext(Subject subject, GSSName gssName)
                    throws GSSException, PrivilegedActionException {
                return contextFactory.create(subject, gssName);
            }
        };
    }

    private static Callable<Subject> sequence(Subject... subjects) {
        return sequence(subjects, new AtomicInteger());
    }

    private static Callable<Subject> sequence(Subject[] subjects, AtomicInteger calls) {
        return () -> subjects[Math.min(calls.getAndIncrement(), subjects.length - 1)];
    }

    private static Subject subjectWithTgt(Instant endTime) {
        return subjectWithTgt(tgt(endTime));
    }

    private static Subject subjectWithTgt(KerberosTicket ticket) {
        Subject subject = new Subject();
        subject.getPrivateCredentials().add(ticket);
        return subject;
    }

    private static KerberosTicket tgt(Instant endTime) {
        KerberosTicket ticket = mock(KerberosTicket.class);
        when(ticket.getServer()).thenReturn(new KerberosPrincipal("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        when(ticket.getEndTime()).thenReturn(endTime == null ? null : Date.from(endTime));
        return ticket;
    }

    private static GSSException gssException(int majorCode) {
        return new GSSException(majorCode);
    }

    private static GSSContext tokenContext(AtomicReference<Subject> tokenSubject, AtomicInteger tokenCalls) {
        return (GSSContext) Proxy.newProxyInstance(
                GSSContext.class.getClassLoader(),
                new Class[]{GSSContext.class},
                (proxy, method, args) -> {
                    if ("initSecContext".equals(method.getName()) && args != null && args.length == 3) {
                        tokenSubject.set(currentSubject());
                        if (tokenCalls != null) {
                            tokenCalls.incrementAndGet();
                            throw gssException(GSSException.NO_CRED);
                        }
                        return new byte[]{1};
                    }
                    if ("toString".equals(method.getName())) {
                        return "test-gss-context";
                    }
                    return defaultValue(method.getReturnType());
                });
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

    private static Subject currentSubject() {
        try {
            Method current = Subject.class.getMethod("current");
            return (Subject) current.invoke(null);
        } catch (ReflectiveOperationException e) {
            return Subject.getSubject(AccessController.getContext());
        }
    }

    @FunctionalInterface
    private interface ContextFactory {
        GSSContext create(Subject subject, GSSName gssName) throws GSSException, PrivilegedActionException;
    }
}
