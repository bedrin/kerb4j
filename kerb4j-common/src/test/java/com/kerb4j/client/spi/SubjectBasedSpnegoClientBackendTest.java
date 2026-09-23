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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
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
        MutableClock clock = new MutableClock(NOW);
        SubjectBasedSpnegoClientBackend backend = backend(sequence(initialSubject, refreshedSubject), clock, false);

        assertThrows(IllegalStateException.class, backend::getSubject);
        clock.advance(Duration.ofSeconds(1));
        assertSame(refreshedSubject, backend.getSubject());

        verify(destroyedTgt, never()).getEndTime();
    }

    @Test
    void refreshesTgtWithNullEndTimeWithoutNullPointerException() {
        Subject initialSubject = subjectWithTgt((Instant) null);
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        MutableClock clock = new MutableClock(NOW);
        SubjectBasedSpnegoClientBackend backend = backend(sequence(initialSubject, refreshedSubject), clock, false);

        assertThrows(IllegalStateException.class, backend::getSubject);
        clock.advance(Duration.ofSeconds(1));
        assertSame(refreshedSubject, backend.getSubject());
    }

    @Test
    void selectsHomeRealmTgtRegardlessOfInsertionOrder() {
        KerberosTicket crossRealm = ticket("client@CLIENT.REALM",
                "krbtgt/TARGET.REALM@CLIENT.REALM", NOW.plusSeconds(1200), (byte) 1);
        KerberosTicket homeRealm = ticket("client@CLIENT.REALM",
                "krbtgt/CLIENT.REALM@CLIENT.REALM", NOW.plusSeconds(600), (byte) 2);

        assertSame(homeRealm, selectTgt(subjectWithTickets(crossRealm, homeRealm)));
        assertSame(homeRealm, selectTgt(subjectWithTickets(homeRealm, crossRealm)));
    }

    @Test
    void selectsValidTgtInsteadOfExpiredTgt() {
        KerberosTicket expired = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.minusSeconds(1), (byte) 1);
        KerberosTicket valid = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 2);

        assertSame(valid, selectTgt(subjectWithTickets(expired, valid)));
    }

    @Test
    void acceptsOrdinaryTgtWithStartTimeThirtySecondsInFuture() {
        KerberosTicket futureStart = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);
        when(futureStart.getStartTime()).thenReturn(Date.from(NOW.plusSeconds(30)));

        assertSame(futureStart, selectTgt(subjectWithTickets(futureStart)));
    }

    @Test
    void skipsInvalidPostdatedTgtThatIsNotYetValid() {
        KerberosTicket postdated = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);
        when(postdated.getStartTime()).thenReturn(Date.from(NOW.plusSeconds(30)));
        boolean[] flags = new boolean[32];
        flags[6] = true;
        flags[7] = true;
        when(postdated.getFlags()).thenReturn(flags);
        KerberosTicket valid = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 2);

        assertSame(valid, selectTgt(subjectWithTickets(postdated, valid)));
    }

    @Test
    void skipsDestroyedTgt() {
        KerberosTicket destroyed = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);
        when(destroyed.isDestroyed()).thenReturn(true);
        KerberosTicket valid = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 2);

        assertSame(valid, selectTgt(subjectWithTickets(destroyed, valid)));
        verify(destroyed, never()).getClient();
    }

    @Test
    void skipsTgtsWithMissingClientServerOrEndTime() {
        KerberosTicket missingClient = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);
        when(missingClient.getClient()).thenReturn(null);
        KerberosTicket missingServer = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 2);
        when(missingServer.getServer()).thenReturn(null);
        KerberosTicket missingEndTime = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", null, (byte) 3);
        KerberosTicket valid = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 4);

        assertSame(valid, selectTgt(subjectWithTickets(
                missingClient, missingServer, missingEndTime, valid)));
    }

    @Test
    void selectsLatestExpiryAmongEquivalentValidTgts() {
        KerberosTicket earlier = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 1);
        KerberosTicket later = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 2);

        assertSame(later, selectTgt(subjectWithTickets(earlier, later)));
        assertSame(later, selectTgt(subjectWithTickets(later, earlier)));
    }

    @Test
    void rejectsServiceTicketWithKrbtgtLikePrincipal() {
        KerberosTicket serviceTicket = ticket("client@EXAMPLE.COM",
                "krbtgt-service/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);

        assertNull(selectTgt(subjectWithTickets(serviceTicket)));
    }

    @Test
    void deterministicCrossRealmTieBreakDoesNotDependOnSetOrder() {
        KerberosTicket realmB = ticket("client@CLIENT.REALM",
                "krbtgt/B.REALM@CLIENT.REALM", NOW.plusSeconds(600), (byte) 1);
        KerberosTicket realmA = ticket("client@CLIENT.REALM",
                "krbtgt/A.REALM@CLIENT.REALM", NOW.plusSeconds(600), (byte) 2);

        assertSame(realmA, selectTgt(subjectWithTickets(realmB, realmA)));
        assertSame(realmA, selectTgt(subjectWithTickets(realmA, realmB)));
    }

    @Test
    void skipsTicketDestroyedDuringInspection() {
        KerberosTicket concurrentlyDestroyed = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(1200), (byte) 1);
        when(concurrentlyDestroyed.isDestroyed()).thenReturn(false, false, true);
        KerberosTicket valid = ticket("client@EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@EXAMPLE.COM", NOW.plusSeconds(600), (byte) 2);

        assertSame(valid, selectTgt(subjectWithTickets(concurrentlyDestroyed, valid)));
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
    void nearExpiryRefreshIsSharedAndRetriedAtAdaptivePoint() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject stillNearExpiry = subjectWithTgt(NOW.plusSeconds(45));
        Subject freshSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch allowRefresh = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return initialSubject;
            }
            if (call == 2) {
                refreshStarted.countDown();
                if (!allowRefresh.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to complete near-expiry refresh");
                }
                return stillNearExpiry;
            }
            return freshSubject;
        }, clock);
        assertSame(initialSubject, backend.getSubject());

        int callerCount = 20;
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
                assertSame(stillNearExpiry, result.get(10, TimeUnit.SECONDS));
            }

            for (int i = 0; i < callerCount; i++) {
                assertSame(stillNearExpiry, backend.getSubject());
            }
            assertEquals(2, supplierCalls.get());

            clock.advance(Duration.ofSeconds(1));
            assertSame(stillNearExpiry, backend.getSubject());
            assertEquals(2, supplierCalls.get());

            clock.advance(Duration.ofMillis(21_500));
            assertSame(freshSubject, backend.getSubject());
            assertSame(freshSubject, backend.getSubject());
            assertEquals(3, supplierCalls.get());
        } finally {
            allowRefresh.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void repeatedSameNearExpiryTicketUsesAdaptiveRetriesAndIsNeverReturnedAfterExpiry() {
        MutableClock clock = new MutableClock(NOW);
        Subject nearExpirySubject = subjectWithTgt(NOW.plusSeconds(30));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return nearExpirySubject;
        }, clock);

        assertSame(nearExpirySubject, backend.getSubject());
        assertSame(nearExpirySubject, backend.getSubject());
        for (int i = 0; i < 14; i++) {
            clock.advance(Duration.ofSeconds(1));
            assertSame(nearExpirySubject, backend.getSubject());
        }
        assertEquals(2, supplierCalls.get());

        clock.advance(Duration.ofSeconds(1));
        assertSame(nearExpirySubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());

        clock.advance(Duration.ofMillis(7_500));
        assertSame(nearExpirySubject, backend.getSubject());
        assertEquals(4, supplierCalls.get());

        clock.advance(Duration.ofMillis(7_500));
        IllegalStateException failure = assertThrows(IllegalStateException.class, backend::getSubject);
        assertTrue(failure.getMessage().contains("contains no usable Kerberos TGT"));
        assertEquals(5, supplierCalls.get());
    }

    @Test
    void healthySubjectResetsAdaptiveRetryState() {
        MutableClock clock = new MutableClock(NOW);
        Subject nearExpirySubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject healthySubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{nearExpirySubject, healthySubject}, supplierCalls), clock);

        assertSame(nearExpirySubject, backend.getSubject());
        assertSame(healthySubject, backend.getSubject());
        clock.advance(Duration.ofSeconds(30));
        assertSame(healthySubject, backend.getSubject());
        assertEquals(2, supplierCalls.get());
    }

    @Test
    void concurrentCallersUseValidSubjectAfterProactiveFailureAndLaterRetryPublishesOnce() throws Exception {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        Exception expectedCause = new Exception("refresh failed");
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch failureStarted = new CountDownLatch(1);
        CountDownLatch allowFailure = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return initialSubject;
            }
            if (call == 2) {
                failureStarted.countDown();
                if (!allowFailure.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to release refresh failure");
                }
                throw expectedCause;
            }
            return refreshedSubject;
        }, clock);
        assertSame(initialSubject, backend.getSubject());

        int callerCount = 20;
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
            assertTrue(failureStarted.await(10, TimeUnit.SECONDS));
            allowFailure.countDown();

            for (Future<Subject> result : results) {
                assertSame(initialSubject, result.get(10, TimeUnit.SECONDS));
            }

            assertEquals(2, supplierCalls.get());
            assertSame(initialSubject, backend.getSubject());
            clock.advance(Duration.ofMillis(14_999));
            assertSame(initialSubject, backend.getSubject());
            assertEquals(2, supplierCalls.get());

            clock.advance(Duration.ofMillis(1));
            List<Future<Subject>> recoveredResults = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(backend::getSubject))
                    .toList();
            for (Future<Subject> result : recoveredResults) {
                assertSame(refreshedSubject, result.get(10, TimeUnit.SECONDS));
            }
            assertEquals(3, supplierCalls.get());
        } finally {
            allowFailure.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void runtimeProactiveRefreshFailureRetainsUsableSubject() {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return initialSubject;
            }
            if (call == 2) {
                throw new IllegalStateException("refresh failed");
            }
            return refreshedSubject;
        }, clock);
        assertSame(initialSubject, backend.getSubject());

        assertSame(initialSubject, backend.getSubject());
        assertSame(initialSubject, backend.getSubject());
        clock.advance(Duration.ofSeconds(15));
        assertSame(refreshedSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void invalidProactiveRefreshResultRetainsUsableSubject() {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{initialSubject, new Subject(), refreshedSubject}, supplierCalls), clock, false);

        assertSame(initialSubject, backend.getSubject());
        assertSame(initialSubject, backend.getSubject());
        assertSame(initialSubject, backend.getSubject());
        assertEquals(2, supplierCalls.get());

        clock.advance(Duration.ofSeconds(15));
        assertSame(refreshedSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void interruptedSupplierDoesNotCorruptBackendState() throws Exception {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch supplierStarted = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call == 1) {
                return initialSubject;
            }
            if (call == 2) {
                supplierStarted.countDown();
                new CountDownLatch(1).await();
            }
            return refreshedSubject;
        });
        assertSame(initialSubject, backend.getSubject());
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        AtomicBoolean interruptRestored = new AtomicBoolean();
        Thread refreshThread = new Thread(() -> {
            try {
                backend.getSubject();
            } catch (RuntimeException e) {
                failure.set(e);
                interruptRestored.set(Thread.currentThread().isInterrupted());
            }
        });

        refreshThread.start();
        assertTrue(supplierStarted.await(10, TimeUnit.SECONDS));
        refreshThread.interrupt();
        refreshThread.join(TimeUnit.SECONDS.toMillis(10));

        assertFalse(refreshThread.isAlive());
        assertTrue(failure.get().getCause() instanceof InterruptedException);
        assertTrue(interruptRestored.get());
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
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            supplierCalls.incrementAndGet();
            return new Subject();
        }, clock, false);

        IllegalStateException firstFailure = assertThrows(IllegalStateException.class, backend::getSubject);
        IllegalStateException secondFailure = assertThrows(IllegalStateException.class, backend::getSubject);

        assertTrue(firstFailure.getMessage().contains("contains no usable Kerberos TGT"));
        assertSame(firstFailure, secondFailure);
        assertEquals(1, supplierCalls.get());

        clock.advance(Duration.ofSeconds(1));
        IllegalStateException laterFailure = assertThrows(IllegalStateException.class, backend::getSubject);
        assertTrue(laterFailure.getMessage().contains("contains no usable Kerberos TGT"));
        assertNotSame(firstFailure, laterFailure);
        assertEquals(2, supplierCalls.get());
    }

    @Test
    void concurrentInitialNoTgtValidationFailureIsSharedAndLaterRecoveryIsPublishedOnce() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        CountDownLatch invalidSubjectReady = new CountDownLatch(1);
        CountDownLatch allowInvalidSubject = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            if (supplierCalls.incrementAndGet() == 1) {
                invalidSubjectReady.countDown();
                if (!allowInvalidSubject.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to return invalid Subject");
                }
                return new Subject();
            }
            return recoveredSubject;
        }, clock, false);

        int callerCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Subject>> failedResults = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return backend.getSubject();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(invalidSubjectReady.await(10, TimeUnit.SECONDS));
            allowInvalidSubject.countDown();

            IllegalStateException sharedFailure = null;
            for (Future<Subject> result : failedResults) {
                ExecutionException e = assertThrows(ExecutionException.class,
                        () -> result.get(10, TimeUnit.SECONDS));
                assertTrue(e.getCause() instanceof IllegalStateException);
                if (sharedFailure == null) {
                    sharedFailure = (IllegalStateException) e.getCause();
                } else {
                    assertSame(sharedFailure, e.getCause());
                }
            }
            assertEquals(1, supplierCalls.get());
            assertSame(sharedFailure, assertThrows(IllegalStateException.class, backend::getSubject));

            clock.advance(Duration.ofSeconds(1));
            List<Future<Subject>> recoveredResults = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(backend::getSubject))
                    .toList();
            for (Future<Subject> result : recoveredResults) {
                assertSame(recoveredSubject, result.get(10, TimeUnit.SECONDS));
            }
            assertEquals(2, supplierCalls.get());
        } finally {
            allowInvalidSubject.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void nullSubjectFailureIsClearSharedAndRetryable() {
        MutableClock clock = new MutableClock(NOW);
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() ->
                supplierCalls.getAndIncrement() == 0 ? null : recoveredSubject, clock, false);

        IllegalStateException firstFailure = assertThrows(IllegalStateException.class, backend::getSubject);
        assertTrue(firstFailure.getMessage().contains("returned null"));
        assertSame(firstFailure, assertThrows(IllegalStateException.class, backend::getSubject));
        assertEquals(1, supplierCalls.get());

        clock.advance(Duration.ofSeconds(1));
        assertSame(recoveredSubject, backend.getSubject());
        assertEquals(2, supplierCalls.get());
    }

    @Test
    void noTgtRefreshNeverReturnsExpiredSubjectAndLaterValidResultRecovers() {
        Subject expiredSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject invalidRefreshedSubject = new Subject();
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger supplierCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(
                sequence(new Subject[]{expiredSubject, invalidRefreshedSubject, recoveredSubject}, supplierCalls),
                clock, false);
        assertSame(expiredSubject, backend.getSubject());
        clock.advance(Duration.ofSeconds(30));

        IllegalStateException failure = assertThrows(IllegalStateException.class, backend::getSubject);

        assertTrue(failure.getMessage().contains("contains no usable Kerberos TGT"));
        assertSame(failure, assertThrows(IllegalStateException.class, backend::getSubject));
        clock.advance(Duration.ofSeconds(1));
        assertSame(recoveredSubject, backend.getSubject());
        assertSame(recoveredSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
    }

    @Test
    void concurrentCallersShareFailureWhenOldTgtExpiresDuringBlockedRefresh() throws Exception {
        Subject expiredSubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject recoveredSubject = subjectWithTgt(NOW.plusSeconds(600));
        Exception expectedCause = new Exception("refresh failed after old TGT expired");
        MutableClock clock = new MutableClock(NOW);
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
                throw expectedCause;
            }
            return recoveredSubject;
        }, clock, false);
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
            clock.advance(Duration.ofSeconds(30));
            allowInvalidRefresh.countDown();

            RuntimeException sharedFailure = null;
            for (Future<Subject> result : results) {
                ExecutionException e = assertThrows(ExecutionException.class,
                        () -> result.get(10, TimeUnit.SECONDS));
                assertTrue(e.getCause() instanceof RuntimeException);
                assertSame(expectedCause, e.getCause().getCause());
                if (sharedFailure == null) {
                    sharedFailure = (RuntimeException) e.getCause();
                } else {
                    assertSame(sharedFailure, e.getCause());
                }
            }
            assertEquals(2, supplierCalls.get());
            assertSame(sharedFailure, assertThrows(RuntimeException.class, backend::getSubject));

            clock.advance(Duration.ofSeconds(1));
            for (int i = 0; i < callerCount; i++) {
                assertSame(recoveredSubject, backend.getSubject());
            }
        } finally {
            allowInvalidRefresh.countDown();
            executor.shutdownNow();
        }

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
    void noCredInvalidationBypassesAdaptiveRetryTime() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Subject nearExpirySubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() ->
                        supplierCalls.incrementAndGet() < 3 ? nearExpirySubject : refreshedSubject,
                clock, (subject, ignored) -> {
                    if (contextCalls.incrementAndGet() == 1) {
                        throw new PrivilegedActionException(gssException(GSSException.NO_CRED));
                    }
                    return tokenContext(new AtomicReference<>(), null);
                });

        assertSame(nearExpirySubject, backend.getSubject());
        assertSame(nearExpirySubject, backend.getSubject());
        assertEquals(2, supplierCalls.get());

        createInitiatorContext(backend);

        assertSame(refreshedSubject, backend.getSubject());
        assertEquals(3, supplierCalls.get());
        assertEquals(2, contextCalls.get());
    }

    @Test
    void noCredInvalidatesSamePairRetainedAfterProactiveFailure() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Subject nearExpirySubject = subjectWithTgt(NOW.plusSeconds(30));
        Subject refreshedSubject = subjectWithTgt(NOW.plusSeconds(600));
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        AtomicReference<Subject> successfulContextSubject = new AtomicReference<>();
        CountDownLatch contextStarted = new CountDownLatch(1);
        CountDownLatch allowNoCred = new CountDownLatch(1);
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            int call = supplierCalls.incrementAndGet();
            if (call <= 2) {
                return nearExpirySubject;
            }
            if (call == 3) {
                throw new Exception("proactive refresh failed");
            }
            return refreshedSubject;
        }, clock, (subject, ignored) -> {
            if (contextCalls.incrementAndGet() == 1) {
                contextStarted.countDown();
                try {
                    if (!allowNoCred.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to release NO_CRED failure");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new PrivilegedActionException(e);
                }
                throw new PrivilegedActionException(gssException(GSSException.NO_CRED));
            }
            successfulContextSubject.set(subject);
            return tokenContext(new AtomicReference<>(), null);
        });

        assertSame(nearExpirySubject, backend.getSubject());
        assertSame(nearExpirySubject, backend.getSubject());
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<SpnegoContext> contextResult = executor.submit(() -> createInitiatorContext(backend));
            assertTrue(contextStarted.await(10, TimeUnit.SECONDS));

            clock.advance(Duration.ofSeconds(15));
            assertSame(nearExpirySubject, backend.getSubject());
            allowNoCred.countDown();

            try (SpnegoContext ignored = contextResult.get(10, TimeUnit.SECONDS)) {
                assertSame(refreshedSubject, successfulContextSubject.get());
            }
        } finally {
            allowNoCred.countDown();
            executor.shutdownNow();
        }

        assertEquals(4, supplierCalls.get());
        assertEquals(2, contextCalls.get());
    }

    @Test
    void explicitlyInvalidatedTgtIsNotUsedAsFallbackWhenRefreshFails() throws Exception {
        Subject initialSubject = subjectWithTgt(NOW.plusSeconds(600));
        Exception expectedCause = new Exception("mandatory refresh failed");
        AtomicInteger supplierCalls = new AtomicInteger();
        AtomicInteger contextCalls = new AtomicInteger();
        SubjectBasedSpnegoClientBackend backend = backend(() -> {
            if (supplierCalls.incrementAndGet() == 1) {
                return initialSubject;
            }
            throw expectedCause;
        }, (subject, ignored) -> {
            contextCalls.incrementAndGet();
            throw new PrivilegedActionException(gssException(GSSException.NO_CRED));
        });
        assertSame(initialSubject, backend.getSubject());

        RuntimeException failure = assertThrows(RuntimeException.class,
                () -> createInitiatorContext(backend));

        assertSame(expectedCause, failure.getCause());
        assertEquals(2, supplierCalls.get());
        assertEquals(1, contextCalls.get());
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

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier, Clock clock) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, clock);
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier, boolean acceptOnly) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, CLOCK, acceptOnly);
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier, Clock clock,
                                                            boolean acceptOnly) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, clock, acceptOnly);
    }

    private static SpnegoContext createInitiatorContext(SubjectBasedSpnegoClientBackend backend)
            throws PrivilegedActionException, GSSException {
        return backend.createInitiatorContext(null, mock(GSSName.class));
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier,
                                                            ContextFactory contextFactory) {
        return backend(supplier, CLOCK, contextFactory);
    }

    private static SubjectBasedSpnegoClientBackend backend(Callable<Subject> supplier, Clock clock,
                                                            ContextFactory contextFactory) {
        return new SubjectBasedSpnegoClientBackend("test", supplier, clock) {
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
        return subjectWithTickets(ticket);
    }

    private static Subject subjectWithTickets(KerberosTicket... tickets) {
        Subject subject = new Subject();
        subject.getPrivateCredentials().addAll(List.of(tickets));
        return subject;
    }

    private static KerberosTicket tgt(Instant endTime) {
        return ticket("client@EXAMPLE.COM", "krbtgt/EXAMPLE.COM@EXAMPLE.COM", endTime, (byte) 1);
    }

    private static KerberosTicket ticket(String clientName, String serverName, Instant endTime, byte encoding) {
        KerberosTicket ticket = mock(KerberosTicket.class);
        when(ticket.getClient()).thenReturn(new KerberosPrincipal(clientName));
        when(ticket.getServer()).thenReturn(new KerberosPrincipal(serverName));
        when(ticket.getStartTime()).thenReturn(Date.from(NOW.minusSeconds(60)));
        when(ticket.getEndTime()).thenReturn(endTime == null ? null : Date.from(endTime));
        when(ticket.getFlags()).thenReturn(new boolean[32]);
        when(ticket.getEncoded()).thenReturn(new byte[]{encoding});
        return ticket;
    }

    private static KerberosTicket selectTgt(Subject subject) {
        return SubjectBasedSpnegoClientBackend.selectTgt(subject, CLOCK);
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

    private static class MutableClock extends Clock {

        private final AtomicReference<Instant> instant;
        private final ZoneId zone;

        private MutableClock(Instant instant) {
            this(new AtomicReference<>(instant), ZoneOffset.UTC);
        }

        private MutableClock(AtomicReference<Instant> instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        private void advance(Duration duration) {
            instant.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}
