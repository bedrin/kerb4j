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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SubjectBasedSpnegoClientBackend implements SpnegoClientBackend {

    private static final Logger LOGGER = LoggerFactory.getLogger(SubjectBasedSpnegoClientBackend.class);
    private static final Duration DEFAULT_TGT_REFRESH_MARGIN = Duration.ofSeconds(60);

    private final String implementationName;
    private final AtomicReference<SubjectTgtPair> subjectTgtPairReference = new AtomicReference<>();
    private final AtomicReference<Subject> eternalSubjectReference = new AtomicReference<>();
    private final Callable<Subject> subjectSupplier;
    private final Clock clock;
    private final Duration tgtRefreshMargin;
    private final SubjectMode subjectMode;
    private final Lock authenticateLock = new ReentrantLock();
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
            authenticateLock.lock();
            try {
                eternalSubject = eternalSubjectReference.get();
                if (null != eternalSubject) {
                    return new SubjectSelection(eternalSubject, null);
                }
                subjectTgtPair = subjectTgtPairReference.get();
                if (null == subjectTgtPair || subjectTgtPair.isExpired(clock, tgtRefreshMargin)) {
                    Subject refreshedSubject = subjectSupplier.call();
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
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                authenticateLock.unlock();
            }
        }
        return new SubjectSelection(subjectTgtPair.subject, subjectTgtPair);
    }

    private static SubjectTgtPair findTgtPair(Subject subject) {
        for (KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class)) {
            KerberosPrincipal server = ticket.getServer();
            if (server != null && server.getName().startsWith("krbtgt")) {
                return new SubjectTgtPair(ticket, subject);
            }
        }
        return null;
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

            subjectTgtPairReference.compareAndSet(firstSelection.subjectTgtPair, null);
            try {
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

            if (null == tgt || tgt.isDestroyed()) {
                return true;
            }

            try {
                synchronized (tgt) {
                    Date endTime = tgt.getEndTime();
                    return endTime == null || !endTime.toInstant().isAfter(clock.instant().plus(refreshMargin));
                }
            } catch (Exception e) {
                LOGGER.error("Failed to get Kerberos ticket end time", e);
                return true;
            }
        }
    }

    private static class SubjectSelection {

        private final Subject subject;
        private final SubjectTgtPair subjectTgtPair;

        private SubjectSelection(Subject subject, SubjectTgtPair subjectTgtPair) {
            this.subject = subject;
            this.subjectTgtPair = subjectTgtPair;
        }
    }

    private enum SubjectMode {
        AUTOMATIC,
        INITIATOR,
        ACCEPT_ONLY
    }
}
