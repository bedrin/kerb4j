package com.kerb4j.client.spi;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.common.util.JreVendor;
import com.kerb4j.common.util.SpnegoProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SubjectBasedSpnegoClientBackend implements SpnegoClientBackend {

    private static final Duration DEFAULT_TGT_REFRESH_MARGIN = Duration.ofSeconds(60);
    // Supplier failures are shared for one second; the next request after that may retry without sleeping.
    private static final Duration REFRESH_FAILURE_COOLDOWN = Duration.ofSeconds(1);

    private final String implementationName;
    private final AtomicReference<SubjectTgtPair> subjectTgtPairReference = new AtomicReference<>();
    // Accept-only Subjects have no TGT and therefore no expiry time to drive refresh.
    private final AtomicReference<Subject> eternalSubjectReference = new AtomicReference<>();
    private final Callable<Subject> subjectSupplier;
    private final Clock clock;
    private final Duration tgtRefreshMargin;
    private final SubjectMode subjectMode;
    private final Lock authenticateLock = new ReentrantLock();
    // Guarded by authenticateLock and scoped to the exact cache entry whose refresh failed.
    private @Nullable RefreshFailure refreshFailure;
    // Guarded by authenticateLock; prevents a legacy automatic initiator from becoming accept-only after refresh.
    private boolean tgtWasPublished;

    public SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier) {
        this(implementationName, subjectSupplier, Clock.systemUTC(), DEFAULT_TGT_REFRESH_MARGIN, SubjectMode.AUTOMATIC);
    }

    /**
     * Internal constructor for providers that know whether their login configuration is accept-only.
     *
     * @param implementationName backend implementation name
     * @param subjectSupplier authenticated Subject supplier
     * @param acceptOnly whether the supplied Subject is intentionally accept-only
     */
    protected SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                              boolean acceptOnly) {
        this(implementationName, subjectSupplier, Clock.systemUTC(), DEFAULT_TGT_REFRESH_MARGIN,
                acceptOnly ? SubjectMode.ACCEPT_ONLY : SubjectMode.INITIATOR);
    }

    // Package-private clock overloads keep expiry tests deterministic without expanding the public API.
    SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                    @NonNull Clock clock) {
        this(implementationName, subjectSupplier, clock, DEFAULT_TGT_REFRESH_MARGIN, SubjectMode.AUTOMATIC);
    }

    SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                    @NonNull Clock clock, boolean acceptOnly) {
        this(implementationName, subjectSupplier, clock, DEFAULT_TGT_REFRESH_MARGIN,
                acceptOnly ? SubjectMode.ACCEPT_ONLY : SubjectMode.INITIATOR);
    }

    SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                    @NonNull Clock clock, @NonNull Duration tgtRefreshMargin) {
        this(implementationName, subjectSupplier, clock, tgtRefreshMargin, SubjectMode.AUTOMATIC);
    }

    private SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                             @NonNull Clock clock, @NonNull Duration tgtRefreshMargin,
                                             @NonNull SubjectMode subjectMode) {
        this.implementationName = implementationName;
        this.subjectSupplier = subjectSupplier;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tgtRefreshMargin = requireNonNegative(tgtRefreshMargin);
        this.subjectMode = Objects.requireNonNull(subjectMode, "subjectMode");
    }

    @Override
    public String getImplementationName() {
        return implementationName;
    }

    @Override
    public Subject getSubject() {
        return getSubjectSelection().subject;
    }

    private SubjectSelection getSubjectSelection() {
        Subject eternalSubject = eternalSubjectReference.get();
        if (null != eternalSubject) {
            return new SubjectSelection(eternalSubject, null);
        }
        SubjectTgtPair subjectTgtPair = subjectTgtPairReference.get();
        if (null == subjectTgtPair || subjectTgtPair.isExpired(clock, tgtRefreshMargin)) {
            Instant refreshRequestedAt = clock.instant();
            authenticateLock.lock();
            try {
                eternalSubject = eternalSubjectReference.get();
                if (null != eternalSubject) {
                    return new SubjectSelection(eternalSubject, null);
                }
                subjectTgtPair = subjectTgtPairReference.get();
                if (null == subjectTgtPair || subjectTgtPair.isExpired(clock, tgtRefreshMargin)) {
                    throwCachedRefreshFailure(subjectTgtPair, refreshRequestedAt);
                    Subject refreshedSubject = callSubjectSupplier(subjectTgtPair);
                    refreshFailure = null;
                    SubjectTgtPair refreshedPair = findTgtPair(refreshedSubject);
                    if (refreshedPair != null) {
                        subjectTgtPairReference.set(refreshedPair);
                        tgtWasPublished = true;
                        return new SubjectSelection(refreshedSubject, refreshedPair);
                    }

                    if (subjectMode == SubjectMode.INITIATOR || tgtWasPublished) {
                        throw new IllegalStateException("Refreshed Subject for initiator backend '"
                                + implementationName + "' contains no Kerberos TGT");
                    }

                    // Explicit accept-only and legacy automatic backends may cache an initial no-TGT Subject.
                    eternalSubjectReference.set(refreshedSubject);
                    return new SubjectSelection(refreshedSubject, null);
                }
            } finally {
                authenticateLock.unlock();
            }
        }
        return new SubjectSelection(subjectTgtPair.subject, subjectTgtPair);
    }

    private void throwCachedRefreshFailure(@Nullable SubjectTgtPair refreshTarget, Instant refreshRequestedAt) {
        if (refreshFailure == null) {
            return;
        }
        if (refreshFailure.refreshTarget == refreshTarget
                && (refreshRequestedAt.isBefore(refreshFailure.retryAt)
                    || clock.instant().isBefore(refreshFailure.retryAt))) {
            throw refreshFailure.failure;
        }
        refreshFailure = null;
    }

    private Subject callSubjectSupplier(@Nullable SubjectTgtPair refreshTarget) {
        try {
            return subjectSupplier.call();
        } catch (InterruptedException e) {
            // Interruption belongs to the initiating caller and must not become a shared authentication failure.
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (RuntimeException e) {
            refreshFailure = new RefreshFailure(refreshTarget, e,
                    clock.instant().plus(REFRESH_FAILURE_COOLDOWN));
            throw e;
        } catch (Exception e) {
            RuntimeException failure = new RuntimeException(e);
            refreshFailure = new RefreshFailure(refreshTarget, failure,
                    clock.instant().plus(REFRESH_FAILURE_COOLDOWN));
            throw failure;
        }
    }

    private SubjectTgtPair findTgtPair(Subject subject) {
        KerberosTicket tgt = selectTgt(subject, clock);
        return tgt == null ? null : new SubjectTgtPair(tgt, subject);
    }

    static @Nullable KerberosTicket selectTgt(Subject subject, Clock clock) {
        Instant now = clock.instant();
        // Selection is isolated from later changes to the Subject credential set.
        List<KerberosTicket> tickets = new ArrayList<>(subject.getPrivateCredentials(KerberosTicket.class));
        List<TgtCandidate> candidates = new ArrayList<>(tickets.size());
        for (KerberosTicket ticket : tickets) {
            TgtCandidate candidate = inspectTgt(ticket, now);
            if (candidate != null) {
                candidates.add(candidate);
            }
        }

        // Home-realm wins; fallbacks use latest expiry, principal names, then encoded bytes.
        candidates.sort(SubjectBasedSpnegoClientBackend::compareTgtCandidates);
        for (TgtCandidate candidate : candidates) {
            if (candidate.stillMatchesTicket()) {
                return candidate.ticket;
            }
        }
        return null;
    }

    private static @Nullable TgtCandidate inspectTgt(KerberosTicket ticket, Instant now) {
        try {
            if (ticket.isDestroyed()) {
                return null;
            }
            KerberosPrincipal client = ticket.getClient();
            KerberosPrincipal server = ticket.getServer();
            Date startTime = ticket.getStartTime();
            Date endTime = ticket.getEndTime();
            byte[] encoded = ticket.getEncoded();
            if (ticket.isDestroyed() || client == null || server == null || startTime == null || endTime == null
                    || encoded == null || startTime.toInstant().isAfter(now) || !endTime.toInstant().isAfter(now)) {
                return null;
            }

            String clientRealm = client.getRealm();
            String clientName = client.getName();
            String serverRealm = server.getRealm();
            String serverName = server.getName();
            String targetRealm = tgtTargetRealm(serverName, serverRealm);
            if (clientRealm == null || clientName == null || targetRealm == null) {
                return null;
            }
            boolean homeRealm = clientRealm.equals(targetRealm) && clientRealm.equals(serverRealm);
            return new TgtCandidate(ticket, client, server, startTime, endTime, encoded,
                    clientName, serverName, homeRealm);
        } catch (IllegalStateException | NullPointerException ignored) {
            // Destruction can clear ticket fields between individual accessor calls.
            return null;
        }
    }

    private static @Nullable String tgtTargetRealm(String serverName, String serverRealm) {
        if (serverName == null || serverRealm == null) {
            return null;
        }
        String prefix = "krbtgt/";
        String suffix = "@" + serverRealm;
        if (!serverName.startsWith(prefix) || !serverName.endsWith(suffix)) {
            return null;
        }
        String targetRealm = serverName.substring(prefix.length(), serverName.length() - suffix.length());
        return targetRealm.isEmpty() || targetRealm.indexOf('/') >= 0 || targetRealm.indexOf('@') >= 0
                ? null : targetRealm;
    }

    private static int compareTgtCandidates(TgtCandidate left, TgtCandidate right) {
        int comparison = Boolean.compare(right.homeRealm, left.homeRealm);
        if (comparison == 0) {
            comparison = right.endTime.compareTo(left.endTime);
        }
        if (comparison == 0) {
            comparison = left.serverName.compareTo(right.serverName);
        }
        if (comparison == 0) {
            comparison = left.clientName.compareTo(right.clientName);
        }
        return comparison == 0 ? Arrays.compareUnsigned(left.encoded, right.encoded) : comparison;
    }

    static boolean isTicketCurrentAt(@Nullable KerberosTicket ticket, Instant instant) {
        if (ticket == null) {
            return false;
        }
        try {
            if (ticket.isDestroyed()) {
                return false;
            }
            Date startTime = ticket.getStartTime();
            Date endTime = ticket.getEndTime();
            return startTime != null && !startTime.toInstant().isAfter(instant)
                    && endTime != null && endTime.toInstant().isAfter(instant) && !ticket.isDestroyed();
        } catch (IllegalStateException | NullPointerException ignored) {
            return false;
        }
    }

    private static Duration requireNonNegative(Duration duration) {
        Objects.requireNonNull(duration, "tgtRefreshMargin");
        if (duration.isNegative()) {
            throw new IllegalArgumentException("tgtRefreshMargin must not be negative");
        }
        return duration;
    }

    @Override
    public KerberosKey[] getKerberosKeys() {
        Subject subject = getSubject();
        Set<KerberosKey> kerberosKeys = subject.getPrivateCredentials(KerberosKey.class);
        if (!kerberosKeys.isEmpty()) {
            return new ArrayList<>(kerberosKeys).toArray(new KerberosKey[kerberosKeys.size()]);
        } else {
            Set<KerberosPrincipal> kerberosPrincipals = subject.getPrincipals(KerberosPrincipal.class);
            for (KerberosPrincipal kerberosPrincipal : kerberosPrincipals) {
                Set<KeyTab> keyTabs = subject.getPrivateCredentials(KeyTab.class);
                for (KeyTab keyTab : keyTabs) {
                    KerberosKey[] keys = keyTab.getKeys(kerberosPrincipal);
                    if (null != keys && keys.length > 0) {
                        return keys;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public SpnegoContext createContext(SpnegoClient spnegoClient, URL url) throws PrivilegedActionException, GSSException {
        GSSName gssName = SpnegoProvider.getServerName(url);
        return createInitiatorContext(spnegoClient, gssName);
    }

    @Override
    public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
            throws PrivilegedActionException, GSSException, MalformedURLException {
        GSSName gssName = SpnegoProvider.createGSSNameForSPN(spn);
        return createInitiatorContext(spnegoClient, gssName);
    }

    SpnegoContext createInitiatorContext(SpnegoClient spnegoClient, GSSName gssName)
            throws PrivilegedActionException, GSSException {
        SubjectSelection firstSelection = getSubjectSelection();
        try {
            return createInitiatorContext(spnegoClient, gssName, firstSelection.subject);
        } catch (PrivilegedActionException | GSSException firstFailure) {
            if (!isNoCredentialFailure(firstFailure) || firstSelection.subjectTgtPair == null) {
                throw firstFailure;
            }

            // Clear only the pair used by this attempt; a concurrently published replacement must survive.
            subjectTgtPairReference.compareAndSet(firstSelection.subjectTgtPair, null);
            try {
                // No token has been generated yet, so rebuilding credentials and context is safe and bounded.
                SubjectSelection secondSelection = getSubjectSelection();
                return createInitiatorContext(spnegoClient, gssName, secondSelection.subject);
            } catch (PrivilegedActionException | GSSException | RuntimeException secondFailure) {
                if (secondFailure != firstFailure) {
                    secondFailure.addSuppressed(firstFailure);
                }
                throw secondFailure;
            }
        }
    }

    private SpnegoContext createInitiatorContext(SpnegoClient spnegoClient, GSSName gssName, Subject subject)
            throws PrivilegedActionException, GSSException {
        return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, gssName));
    }

    private static boolean isNoCredentialFailure(Throwable failure) {
        // Identity tracking also makes malformed cyclic cause chains safe to inspect.
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && visited.add(cause); cause = cause.getCause()) {
            if (cause instanceof GSSException && ((GSSException) cause).getMajor() == GSSException.NO_CRED) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SpnegoContext createAcceptContext(SpnegoClient spnegoClient) throws PrivilegedActionException {
        Subject subject = getSubject();
        return new SpnegoContext(spnegoClient, subject, Subject.doAs(subject, new PrivilegedExceptionAction<>() {
            @Override
            public GSSContext run() throws Exception {
                final int credentialLifetime;
                if (JreVendor.IS_IBM_JVM) {
                    credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;
                } else {
                    credentialLifetime = GSSCredential.DEFAULT_LIFETIME;
                }

                GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                        null,
                        credentialLifetime,
                        SpnegoProvider.SUPPORTED_OIDS,
                        GSSCredential.ACCEPT_ONLY);

                return SpnegoProvider.GSS_MANAGER.createContext(credential);
            }
        }));
    }

    protected GSSContext getGSSContext(final Subject subject, final GSSName gssName)
            throws GSSException, PrivilegedActionException {
        return Subject.doAs(subject, new PrivilegedExceptionAction<GSSContext>() {
            @Override
            public GSSContext run() throws Exception {
                GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                        null,
                        GSSCredential.DEFAULT_LIFETIME,
                        SpnegoProvider.SUPPORTED_OIDS,
                        GSSCredential.INITIATE_ONLY);

                GSSContext context = SpnegoProvider.GSS_MANAGER.createContext(gssName,
                        SpnegoProvider.SPNEGO_OID,
                        credential,
                        GSSContext.DEFAULT_LIFETIME);

                context.requestMutualAuth(true);
                context.requestConf(true);
                context.requestInteg(true);
                context.requestReplayDet(true);
                context.requestSequenceDet(true);

                return context;
            }
        });
    }

    private static class SubjectTgtPair {

        private final KerberosTicket tgt;
        private final Subject subject;

        private SubjectTgtPair(KerberosTicket tgt, Subject subject) {
            this.tgt = tgt;
            this.subject = subject;
        }

        private boolean isExpired(Clock clock, Duration refreshMargin) {
            return !isTicketCurrentAt(tgt, clock.instant().plus(refreshMargin));
        }
    }

    // Immutable inspection snapshot used to rank tickets without rereading mutable ticket fields.
    private static class TgtCandidate {

        private final KerberosTicket ticket;
        private final KerberosPrincipal client;
        private final KerberosPrincipal server;
        private final Date startTime;
        private final Date endTime;
        private final byte[] encoded;
        private final String clientName;
        private final String serverName;
        private final boolean homeRealm;

        private TgtCandidate(KerberosTicket ticket, KerberosPrincipal client, KerberosPrincipal server,
                             Date startTime, Date endTime, byte[] encoded,
                             String clientName, String serverName, boolean homeRealm) {
            this.ticket = ticket;
            this.client = client;
            this.server = server;
            this.startTime = startTime;
            this.endTime = endTime;
            this.encoded = encoded;
            this.clientName = clientName;
            this.serverName = serverName;
            this.homeRealm = homeRealm;
        }

        private boolean stillMatchesTicket() {
            try {
                return !ticket.isDestroyed()
                        && client.equals(ticket.getClient())
                        && server.equals(ticket.getServer())
                        && startTime.equals(ticket.getStartTime())
                        && endTime.equals(ticket.getEndTime())
                        && Arrays.equals(encoded, ticket.getEncoded())
                        && !ticket.isDestroyed();
            } catch (IllegalStateException | NullPointerException ignored) {
                return false;
            }
        }
    }

    // Callers joining one failed refresh share its exception; the first request after retryAt may try again.
    private static class RefreshFailure {

        private final @Nullable SubjectTgtPair refreshTarget;
        private final RuntimeException failure;
        private final Instant retryAt;

        private RefreshFailure(@Nullable SubjectTgtPair refreshTarget, RuntimeException failure, Instant retryAt) {
            this.refreshTarget = refreshTarget;
            this.failure = failure;
            this.retryAt = retryAt;
        }
    }

    // Couples a Subject to its cache entry so recovery can invalidate exactly the credentials that failed.
    private static class SubjectSelection {

        private final Subject subject;
        private final SubjectTgtPair subjectTgtPair;

        private SubjectSelection(Subject subject, SubjectTgtPair subjectTgtPair) {
            this.subject = subject;
            this.subjectTgtPair = subjectTgtPair;
        }
    }

    // AUTOMATIC preserves the historic public-constructor behavior for an initial no-TGT Subject.
    private enum SubjectMode {
        AUTOMATIC,
        INITIATOR,
        ACCEPT_ONLY
    }
}
