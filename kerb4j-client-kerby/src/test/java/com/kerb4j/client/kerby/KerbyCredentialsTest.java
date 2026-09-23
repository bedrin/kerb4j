package com.kerb4j.client.kerby;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KerbyCredentialsTest {

    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void reusesTgtOutsideDefaultRefreshMargin() throws Exception {
        TgtTicket tgt = tgt(NOW.plusSeconds(61));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            requesterCalls.incrementAndGet();
            return tgt;
        });

        assertSame(tgt, credentials.getTgtTicket());
        assertSame(tgt, credentials.getTgtTicket());

        assertEquals(1, requesterCalls.get());
    }

    @Test
    void refreshesTgtInsideDefaultRefreshMargin() throws Exception {
        assertRefreshesAt(NOW.plusSeconds(59));
    }

    @Test
    void refreshesTgtExactlyAtDefaultRefreshMargin() throws Exception {
        assertRefreshesAt(NOW.plusSeconds(60));
    }

    @Test
    void refreshesTgtWithNullEndTimeWithoutNullPointerException() throws Exception {
        TgtTicket initialTgt = tgt(null);
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        MutableClock clock = new MutableClock(NOW);
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                credentials(sequence(initialTgt, refreshedTgt, new AtomicInteger()), clock);

        IllegalStateException failure = assertThrows(IllegalStateException.class, credentials::getTgtTicket);
        assertSame(failure, assertThrows(IllegalStateException.class, credentials::getTgtTicket));
        clock.advance(Duration.ofSeconds(1));
        assertSame(refreshedTgt, credentials.getTgtTicket());
    }

    @Test
    void concurrentCallersTriggerOneRefreshAndReceiveRefreshedTgt() throws Exception {
        TgtTicket initialTgt = tgt(NOW.plusSeconds(30));
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch allowRefresh = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            if (requesterCalls.incrementAndGet() == 1) {
                return initialTgt;
            }
            refreshStarted.countDown();
            if (!allowRefresh.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to complete refresh");
            }
            return refreshedTgt;
        });
        assertSame(initialTgt, credentials.getTgtTicket());

        int callerCount = 32;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<TgtTicket>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return credentials.getTgtTicket();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(refreshStarted.await(10, TimeUnit.SECONDS));
            allowRefresh.countDown();

            for (Future<TgtTicket> result : results) {
                assertSame(refreshedTgt, result.get(10, TimeUnit.SECONDS));
            }
        } finally {
            allowRefresh.countDown();
            executor.shutdownNow();
        }

        assertEquals(2, requesterCalls.get());
    }

    @Test
    void concurrentCallersShareCheckedRefreshFailureAndLaterSuccessfulRetry() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        KrbException expectedFailure = new KrbException("expected refresh failure");
        AtomicInteger requesterCalls = new AtomicInteger();
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch allowFailure = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            if (requesterCalls.incrementAndGet() == 1) {
                requestStarted.countDown();
                if (!allowFailure.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to fail TGT request");
                }
                throw expectedFailure;
            }
            return refreshedTgt;
        }, clock);

        int callerCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<TgtTicket>> failedResults = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return credentials.getTgtTicket();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(requestStarted.await(10, TimeUnit.SECONDS));
            allowFailure.countDown();
            for (Future<TgtTicket> result : failedResults) {
                ExecutionException failure = assertThrows(ExecutionException.class,
                        () -> result.get(10, TimeUnit.SECONDS));
                assertSame(expectedFailure, failure.getCause());
            }
            assertEquals(1, requesterCalls.get());
            assertSame(expectedFailure, assertThrows(KrbException.class, credentials::getTgtTicket));

            clock.advance(Duration.ofSeconds(1));
            List<Future<TgtTicket>> recoveredResults = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(credentials::getTgtTicket))
                    .toList();
            for (Future<TgtTicket> result : recoveredResults) {
                assertSame(refreshedTgt, result.get(10, TimeUnit.SECONDS));
            }
            assertEquals(2, requesterCalls.get());
        } finally {
            allowFailure.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void concurrentCallersShareRuntimeRefreshFailure() throws Exception {
        RuntimeException expectedFailure = new IllegalStateException("runtime refresh failure");
        AtomicInteger requesterCalls = new AtomicInteger();
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch allowFailure = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            requesterCalls.incrementAndGet();
            requestStarted.countDown();
            if (!allowFailure.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to fail TGT request");
            }
            throw expectedFailure;
        });

        int callerCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<TgtTicket>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        start.await();
                        return credentials.getTgtTicket();
                    }))
                    .toList();
            start.countDown();
            assertTrue(requestStarted.await(10, TimeUnit.SECONDS));
            allowFailure.countDown();

            for (Future<TgtTicket> result : results) {
                ExecutionException failure = assertThrows(ExecutionException.class,
                        () -> result.get(10, TimeUnit.SECONDS));
                assertSame(expectedFailure, failure.getCause());
            }
            assertEquals(1, requesterCalls.get());
            assertSame(expectedFailure,
                    assertThrows(IllegalStateException.class, credentials::getTgtTicket));
        } finally {
            allowFailure.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void interruptedRequesterIsNotCachedAndRestoresInterruptStatus() throws Exception {
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        InterruptedException expectedFailure = new InterruptedException("interrupted refresh");
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            if (requesterCalls.incrementAndGet() == 1) {
                throw expectedFailure;
            }
            return refreshedTgt;
        });
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptRestored = new AtomicReference<>(false);
        Thread thread = new Thread(() -> {
            try {
                credentials.getTgtTicket();
            } catch (Throwable e) {
                failure.set(e);
                interruptRestored.set(Thread.currentThread().isInterrupted());
            }
        });

        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(10));

        assertFalse(thread.isAlive());
        assertSame(expectedFailure, failure.get());
        assertTrue(interruptRestored.get());
        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());
    }

    @Test
    void concurrentCallersShareNullTgtValidationFailure() throws Exception {
        AtomicInteger requesterCalls = new AtomicInteger();
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch allowResult = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            requesterCalls.incrementAndGet();
            requestStarted.countDown();
            if (!allowResult.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to return null TGT");
            }
            return null;
        });

        int callerCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        IllegalStateException sharedFailure = null;
        try {
            List<Future<TgtTicket>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        start.await();
                        return credentials.getTgtTicket();
                    }))
                    .toList();
            start.countDown();
            assertTrue(requestStarted.await(10, TimeUnit.SECONDS));
            allowResult.countDown();

            for (Future<TgtTicket> result : results) {
                ExecutionException failure = assertThrows(ExecutionException.class,
                        () -> result.get(10, TimeUnit.SECONDS));
                assertTrue(failure.getCause() instanceof IllegalStateException);
                if (sharedFailure == null) {
                    sharedFailure = (IllegalStateException) failure.getCause();
                } else {
                    assertSame(sharedFailure, failure.getCause());
                }
            }
        } finally {
            allowResult.countDown();
            executor.shutdownNow();
        }

        assertTrue(sharedFailure.getMessage().contains("returned null"));
        assertSame(sharedFailure, assertThrows(IllegalStateException.class, credentials::getTgtTicket));
        assertEquals(1, requesterCalls.get());
    }

    @Test
    void tgtExpiringDuringAcquisitionIsNotPublishedAndFailureIsShared() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket expiredAtCompletion = tgt(NOW.plusSeconds(1));
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            if (requesterCalls.incrementAndGet() == 1) {
                clock.advance(Duration.ofSeconds(2));
                return expiredAtCompletion;
            }
            return refreshedTgt;
        }, clock);

        IllegalStateException firstFailure = assertThrows(IllegalStateException.class, credentials::getTgtTicket);
        assertTrue(firstFailure.getMessage().contains("expired TGT"));
        assertSame(firstFailure, assertThrows(IllegalStateException.class, credentials::getTgtTicket));
        assertEquals(1, requesterCalls.get());

        clock.advance(Duration.ofSeconds(1));
        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());
    }

    @Test
    void invalidatingOldTgtMakesItsCachedRefreshFailureIrrelevant() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket oldTgt = tgt(NOW.plusSeconds(30));
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        KrbException expectedFailure = new KrbException("old generation failed");
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            int call = requesterCalls.incrementAndGet();
            if (call == 1) {
                return oldTgt;
            }
            if (call == 2) {
                throw expectedFailure;
            }
            return refreshedTgt;
        }, clock);

        assertSame(oldTgt, credentials.getTgtTicket());
        assertSame(expectedFailure, assertThrows(KrbException.class, credentials::getTgtTicket));
        credentials.invalidateTgtTicket(oldTgt);

        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertEquals(3, requesterCalls.get());
    }

    @Test
    void nearExpiryRefreshIsSharedAndRetriedAtAdaptivePoint() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket initialTgt = tgt(NOW.plusSeconds(30));
        TgtTicket stillNearExpiry = tgt(NOW.plusSeconds(45));
        TgtTicket freshTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch allowRefresh = new CountDownLatch(1);
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            int call = requesterCalls.incrementAndGet();
            if (call == 1) {
                return initialTgt;
            }
            if (call == 2) {
                refreshStarted.countDown();
                if (!allowRefresh.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to complete near-expiry refresh");
                }
                return stillNearExpiry;
            }
            return freshTgt;
        }, clock);
        assertSame(initialTgt, credentials.getTgtTicket());

        int callerCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(callerCount);
        CountDownLatch callersReady = new CountDownLatch(callerCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<TgtTicket>> results = java.util.stream.IntStream.range(0, callerCount)
                    .mapToObj(ignored -> executor.submit(() -> {
                        callersReady.countDown();
                        start.await();
                        return credentials.getTgtTicket();
                    }))
                    .toList();

            assertTrue(callersReady.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertTrue(refreshStarted.await(10, TimeUnit.SECONDS));
            allowRefresh.countDown();
            for (Future<TgtTicket> result : results) {
                assertSame(stillNearExpiry, result.get(10, TimeUnit.SECONDS));
            }

            for (int i = 0; i < callerCount; i++) {
                assertSame(stillNearExpiry, credentials.getTgtTicket());
            }
            assertEquals(2, requesterCalls.get());

            clock.advance(Duration.ofSeconds(1));
            assertSame(stillNearExpiry, credentials.getTgtTicket());
            assertEquals(2, requesterCalls.get());

            clock.advance(Duration.ofMillis(21_500));
            assertSame(freshTgt, credentials.getTgtTicket());
            assertSame(freshTgt, credentials.getTgtTicket());
            assertEquals(3, requesterCalls.get());
        } finally {
            allowRefresh.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void repeatedSameNearExpiryTgtUsesAdaptiveRetriesAndIsNeverReturnedAfterExpiry() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket nearExpiryTgt = tgt(NOW.plusSeconds(30));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() -> {
            requesterCalls.incrementAndGet();
            return nearExpiryTgt;
        }, clock);

        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        for (int i = 0; i < 14; i++) {
            clock.advance(Duration.ofSeconds(1));
            assertSame(nearExpiryTgt, credentials.getTgtTicket());
        }
        assertEquals(2, requesterCalls.get());

        clock.advance(Duration.ofSeconds(1));
        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        assertEquals(3, requesterCalls.get());

        clock.advance(Duration.ofMillis(7_500));
        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        assertEquals(4, requesterCalls.get());

        clock.advance(Duration.ofMillis(7_500));
        assertThrows(IllegalStateException.class, credentials::getTgtTicket);
        assertEquals(5, requesterCalls.get());
    }

    @Test
    void invalidatingCurrentTgtForcesNormalRequesterRefresh() throws Exception {
        TgtTicket failedTgt = tgt(NOW.plusSeconds(600));
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                credentials(sequence(failedTgt, refreshedTgt, requesterCalls));

        assertSame(failedTgt, credentials.getTgtTicket());
        credentials.invalidateTgtTicket(failedTgt);

        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());
    }

    @Test
    void invalidatingNearExpiryTgtBypassesAdaptiveRetryTime() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket failedTgt = tgt(NOW.plusSeconds(30));
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(() ->
                requesterCalls.incrementAndGet() < 3 ? failedTgt : refreshedTgt, clock);

        assertSame(failedTgt, credentials.getTgtTicket());
        assertSame(failedTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());

        credentials.invalidateTgtTicket(failedTgt);
        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertEquals(3, requesterCalls.get());
    }

    @Test
    void healthyTgtResetsAdaptiveRetryState() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        TgtTicket nearExpiryTgt = tgt(NOW.plusSeconds(30));
        TgtTicket healthyTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials = credentials(
                sequence(nearExpiryTgt, healthyTgt, requesterCalls), clock);

        assertSame(nearExpiryTgt, credentials.getTgtTicket());
        assertSame(healthyTgt, credentials.getTgtTicket());
        clock.advance(Duration.ofSeconds(30));
        assertSame(healthyTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());
    }

    @Test
    void staleTgtInvalidationDoesNotClearNewerTgt() throws Exception {
        TgtTicket staleTgt = tgt(NOW.plusSeconds(600));
        TgtTicket freshTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                credentials(sequence(staleTgt, freshTgt, requesterCalls));

        assertSame(staleTgt, credentials.getTgtTicket());
        credentials.invalidateTgtTicket(staleTgt);
        assertSame(freshTgt, credentials.getTgtTicket());

        credentials.invalidateTgtTicket(staleTgt);

        assertSame(freshTgt, credentials.getTgtTicket());
        assertEquals(2, requesterCalls.get());
    }

    private static void assertRefreshesAt(Instant endTime) throws Exception {
        TgtTicket initialTgt = tgt(endTime);
        TgtTicket refreshedTgt = tgt(NOW.plusSeconds(600));
        AtomicInteger requesterCalls = new AtomicInteger();
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                credentials(sequence(initialTgt, refreshedTgt, requesterCalls));

        assertSame(initialTgt, credentials.getTgtTicket());
        assertSame(refreshedTgt, credentials.getTgtTicket());
        assertSame(refreshedTgt, credentials.getTgtTicket());

        assertEquals(2, requesterCalls.get());
    }

    private static KerbySpnegoClientProvider.KerbyCredentials credentials(Callable<TgtTicket> requester) {
        return new KerbySpnegoClientProvider.KerbyCredentials(requester, CLOCK);
    }

    private static KerbySpnegoClientProvider.KerbyCredentials credentials(Callable<TgtTicket> requester,
                                                                           Clock clock) {
        return new KerbySpnegoClientProvider.KerbyCredentials(requester, clock);
    }

    private static Callable<TgtTicket> sequence(TgtTicket first, TgtTicket second, AtomicInteger calls) {
        return () -> calls.getAndIncrement() == 0 ? first : second;
    }

    private static TgtTicket tgt(Instant endTime) {
        EncKdcRepPart encKdcRepPart = mock(EncKdcRepPart.class);
        when(encKdcRepPart.getEndTime()).thenReturn(endTime == null ? null : new KerberosTime(endTime.toEpochMilli()));
        TgtTicket tgt = mock(TgtTicket.class);
        when(tgt.getEncKdcRepPart()).thenReturn(encKdcRepPart);
        return tgt;
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
