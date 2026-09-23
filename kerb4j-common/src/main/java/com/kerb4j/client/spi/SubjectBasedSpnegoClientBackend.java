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
    private static final Duration REFRESH_FAILURE_COOLDOWN = Duration.ofSeconds(1);
    private static final Duration MIN_PROACTIVE_RETRY_DELAY = Duration.ofSeconds(1);
    private static final Duration MAX_PROACTIVE_RETRY_DELAY = Duration.ofSeconds(30);
    private static final int MAX_REFRESH_PUBLICATION_ATTEMPTS = 2;
    private static final int POSTDATED_TICKET_FLAG = 6;
    private static final int INVALID_TICKET_FLAG = 7;

    private final String implementationName;
    private final AtomicReference<SubjectCacheState> subjectStateReference =
            new AtomicReference<>(SubjectCacheState.empty(false));
    private final Callable<Subject> subjectSupplier;
    private final Clock clock;
    private final Duration tgtRefreshMargin;
    private final SubjectMode subjectMode;
    private final Lock authenticateLock = new ReentrantLock();
    // Guarded by authenticateLock and scoped to the exact cache entry whose refresh failed.
    private @Nullable RefreshFailure refreshFailure;

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
        SubjectCacheState state = subjectStateReference.get();
        if (state.requiresAuthentication(clock, tgtRefreshMargin)) {
            Instant refreshRequestedAt = clock.instant();
            authenticateLock.lock();
            try {
                for (int attempt = 0; attempt < MAX_REFRESH_PUBLICATION_ATTEMPTS; attempt++) {
                    state = subjectStateReference.get();
                    if (!state.requiresAuthentication(clock, tgtRefreshMargin)) {
                        return state.selection();
                    }
                    throwCachedRefreshFailure(state, refreshRequestedAt);
                    SubjectSelection refreshedSelection = refreshSubject(state);
                    if (refreshedSelection != null) {
                        return refreshedSelection;
                    }
                }

                state = subjectStateReference.get();
                if (!state.requiresAuthentication(clock, tgtRefreshMargin)) {
                    return state.selection();
                }
                throw new IllegalStateException("Subject cache changed during two authentication attempts for backend '"
                        + implementationName + "'");
            } finally {
                authenticateLock.unlock();
            }
        }
        return state.selection();
    }

    private @Nullable SubjectSelection refreshSubject(SubjectCacheState refreshTarget) {
        try {
            Subject refreshedSubject = subjectSupplier.call();
            if (refreshedSubject == null) {
                throw new IllegalStateException("Subject supplier for backend '" + implementationName
                        + "' returned null");
            }

            Instant refreshedAt = clock.instant();
            KerberosTicket refreshedTgt = selectTgt(refreshedSubject, clock);
            Instant refreshedTgtEndTime = ticketEndTime(refreshedTgt);
            SubjectCacheState refreshedState;
            if (refreshedTgt != null && refreshedTgtEndTime != null
                    && isTicketUsableAt(refreshedTgt, refreshedAt)) {
                // Retry halfway through the remaining lifetime, with bounds that avoid request-rate polling.
                Instant retryAt = refreshTarget.tgtWasPublished
                        && !isTicketUsableAt(refreshedTgt, refreshedAt.plus(tgtRefreshMargin))
                        ? nextProactiveRefreshAt(refreshedAt, refreshedTgtEndTime) : refreshedAt;
                refreshedState = SubjectCacheState.withTgt(refreshedSubject, refreshedTgt, retryAt);
            } else if (subjectMode == SubjectMode.INITIATOR || refreshTarget.tgtWasPublished) {
                throw new IllegalStateException("Refreshed Subject for initiator backend '"
                        + implementationName + "' contains no usable Kerberos TGT");
            } else {
                // Explicit accept-only and legacy automatic backends may cache an initial no-TGT Subject.
                refreshedState = SubjectCacheState.eternal(refreshedSubject);
            }

            if (!subjectStateReference.compareAndSet(refreshTarget, refreshedState)) {
                // Invalidation won while authentication was in flight; discard this result and re-read the cache.
                return null;
            }
            refreshFailure = null;
            return refreshedState.selection();
        } catch (InterruptedException e) {
            // Interruption belongs to the initiating caller and must not become a shared authentication failure.
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (RuntimeException e) {
            return handleRefreshFailure(refreshTarget, e);
        } catch (Exception e) {
            RuntimeException failure = new RuntimeException(e);
            return handleRefreshFailure(refreshTarget, failure);
        }
    }

    private SubjectSelection handleRefreshFailure(SubjectCacheState refreshTarget, RuntimeException failure) {
        Instant failedAt = clock.instant();
        SubjectCacheState retainedState = refreshTarget.afterFailedProactiveRefresh(failedAt);
        if (retainedState != null && subjectStateReference.compareAndSet(refreshTarget, retainedState)) {
            // Keep a still-usable TGT, but atomically defer the next proactive attempt.
            refreshFailure = null;
            return retainedState.selection();
        }

        publishRefreshFailure(refreshTarget, failure);
        throw failure;
    }

    private void throwCachedRefreshFailure(SubjectCacheState refreshTarget, Instant refreshRequestedAt) {
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

    private void publishRefreshFailure(SubjectCacheState refreshTarget, RuntimeException failure) {
        refreshFailure = new RefreshFailure(refreshTarget, failure,
                clock.instant().plus(REFRESH_FAILURE_COOLDOWN));
    }

    private static Instant nextProactiveRefreshAt(Instant now, Instant endTime) {
        Duration delay = Duration.between(now, endTime).dividedBy(2);
        if (delay.compareTo(MIN_PROACTIVE_RETRY_DELAY) < 0) {
            delay = MIN_PROACTIVE_RETRY_DELAY;
        } else if (delay.compareTo(MAX_PROACTIVE_RETRY_DELAY) > 0) {
            delay = MAX_PROACTIVE_RETRY_DELAY;
        }
        return now.plus(delay);
    }

    private static @Nullable Instant ticketEndTime(@Nullable KerberosTicket ticket) {
        try {
            Date endTime = ticket == null || ticket.isDestroyed() ? null : ticket.getEndTime();
            return endTime == null ? null : endTime.toInstant();
        } catch (IllegalStateException | NullPointerException ignored) {
            return null;
        }
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
            boolean[] flags = ticket.getFlags();
            byte[] encoded = ticket.getEncoded();
            if (ticket.isDestroyed() || client == null || server == null || startTime == null || endTime == null
                    || encoded == null || !endTime.toInstant().isAfter(now)
                    || hasFlag(flags, INVALID_TICKET_FLAG)
                    || hasFlag(flags, POSTDATED_TICKET_FLAG) && startTime.toInstant().isAfter(now)) {
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
            return new TgtCandidate(ticket, client, server, startTime, endTime, flags, encoded,
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

    static boolean isTicketUsableAt(@Nullable KerberosTicket ticket, Instant instant) {
        if (ticket == null) {
            return false;
        }
        try {
            if (ticket.isDestroyed()) {
                return false;
            }
            Date startTime = ticket.getStartTime();
            Date endTime = ticket.getEndTime();
            boolean[] flags = ticket.getFlags();
            return startTime != null && endTime != null && endTime.toInstant().isAfter(instant)
                    && !hasFlag(flags, INVALID_TICKET_FLAG)
                    && (!hasFlag(flags, POSTDATED_TICKET_FLAG) || !startTime.toInstant().isAfter(instant))
                    && !ticket.isDestroyed();
        } catch (IllegalStateException | NullPointerException ignored) {
            return false;
        }
    }

    private static boolean hasFlag(@Nullable boolean[] flags, int index) {
        return flags != null && flags.length > index && flags[index];
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
            if (!isNoCredentialFailure(firstFailure) || firstSelection.cacheState.tgt == null) {
                throw firstFailure;
            }

            invalidateSubjectTgtPair(firstSelection.cacheState);
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

    private void invalidateSubjectTgtPair(SubjectCacheState failedState) {
        SubjectCacheState currentState = subjectStateReference.get();
        while (currentState.hasSameSubjectTgt(failedState)) {
            // Metadata-only fallback states retain the same pair; genuinely newer credentials must survive.
            if (subjectStateReference.compareAndSet(currentState, currentState.withoutTgt())) {
                return;
            }
            currentState = subjectStateReference.get();
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

    // Immutable inspection snapshot used to rank tickets without rereading mutable ticket fields.
    private static class TgtCandidate {

        private final KerberosTicket ticket;
        private final KerberosPrincipal client;
        private final KerberosPrincipal server;
        private final Date startTime;
        private final Date endTime;
        private final boolean[] flags;
        private final byte[] encoded;
        private final String clientName;
        private final String serverName;
        private final boolean homeRealm;

        private TgtCandidate(KerberosTicket ticket, KerberosPrincipal client, KerberosPrincipal server,
                             Date startTime, Date endTime, boolean[] flags, byte[] encoded,
                             String clientName, String serverName, boolean homeRealm) {
            this.ticket = ticket;
            this.client = client;
            this.server = server;
            this.startTime = startTime;
            this.endTime = endTime;
            this.flags = flags;
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
                        && Arrays.equals(flags, ticket.getFlags())
                        && Arrays.equals(encoded, ticket.getEncoded())
                        && !ticket.isDestroyed();
            } catch (IllegalStateException | NullPointerException ignored) {
                return false;
            }
        }
    }

    // Callers joining one failed refresh share its exception; the first request after retryAt may try again.
    private static class RefreshFailure {

        private final SubjectCacheState refreshTarget;
        private final RuntimeException failure;
        private final Instant retryAt;

        private RefreshFailure(SubjectCacheState refreshTarget, RuntimeException failure, Instant retryAt) {
            this.refreshTarget = refreshTarget;
            this.failure = failure;
            this.retryAt = retryAt;
        }
    }

    // One immutable state object makes Subject/TGT publication and refresh-generation identity indivisible.
    private static class SubjectCacheState {

        private final @Nullable Subject subject;
        private final @Nullable KerberosTicket tgt;
        private final boolean eternal;
        private final boolean tgtWasPublished;
        private final Instant proactiveRetryAt;

        private SubjectCacheState(@Nullable Subject subject, @Nullable KerberosTicket tgt, boolean eternal,
                                  boolean tgtWasPublished, Instant proactiveRetryAt) {
            this.subject = subject;
            this.tgt = tgt;
            this.eternal = eternal;
            this.tgtWasPublished = tgtWasPublished;
            this.proactiveRetryAt = proactiveRetryAt;
        }

        private static SubjectCacheState empty(boolean tgtWasPublished) {
            return new SubjectCacheState(null, null, false, tgtWasPublished, Instant.MIN);
        }

        private static SubjectCacheState withTgt(Subject subject, KerberosTicket tgt, Instant proactiveRetryAt) {
            return new SubjectCacheState(subject, tgt, false, true, proactiveRetryAt);
        }

        private static SubjectCacheState eternal(Subject subject) {
            return new SubjectCacheState(subject, null, true, false, Instant.MAX);
        }

        private boolean requiresAuthentication(Clock clock, Duration refreshMargin) {
            if (eternal) {
                return false;
            }
            Instant now = clock.instant();
            if (!isTicketUsableAt(tgt, now)) {
                return true;
            }
            return !isTicketUsableAt(tgt, now.plus(refreshMargin)) && !now.isBefore(proactiveRetryAt);
        }

        private SubjectSelection selection() {
            return new SubjectSelection(Objects.requireNonNull(subject), this);
        }

        private SubjectCacheState withoutTgt() {
            return empty(tgtWasPublished);
        }

        private boolean hasSameSubjectTgt(SubjectCacheState other) {
            return tgt != null && subject == other.subject && tgt == other.tgt;
        }

        private @Nullable SubjectCacheState afterFailedProactiveRefresh(Instant failedAt) {
            Instant endTime = ticketEndTime(tgt);
            if (subject == null || endTime == null || !isTicketUsableAt(tgt, failedAt)) {
                return null;
            }
            return withTgt(subject, Objects.requireNonNull(tgt), nextProactiveRefreshAt(failedAt, endTime));
        }
    }

    // Couples a Subject to its cache state so recovery can invalidate exactly the credentials that failed.
    private static class SubjectSelection {

        private final Subject subject;
        private final SubjectCacheState cacheState;

        private SubjectSelection(Subject subject, SubjectCacheState cacheState) {
            this.subject = subject;
            this.cacheState = cacheState;
        }
    }

    // AUTOMATIC preserves the historic public-constructor behavior for an initial no-TGT Subject.
    private enum SubjectMode {
        AUTOMATIC,
        INITIATOR,
        ACCEPT_ONLY
    }
}
