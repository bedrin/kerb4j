package com.kerb4j.client.kerby;

import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
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
        KerbySpnegoClientProvider.KerbyCredentials credentials =
                credentials(sequence(initialTgt, refreshedTgt, new AtomicInteger()));

        assertSame(initialTgt, credentials.getTgtTicket());
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
}
