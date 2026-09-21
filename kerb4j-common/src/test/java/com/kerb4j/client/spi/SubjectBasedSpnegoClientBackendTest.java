package com.kerb4j.client.spi;

import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
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
}
