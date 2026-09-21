package com.kerb4j.client.spi;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.common.exception.KerberosFailureAnalyzer;
import com.kerb4j.common.util.JreVendor;
import com.kerb4j.common.util.SpnegoProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SubjectBasedSpnegoClientBackend implements SpnegoClientBackend {

    private static final Logger LOGGER = LoggerFactory.getLogger(SubjectBasedSpnegoClientBackend.class);

    private final String implementationName;
    private final AtomicReference<SubjectTgtPair> subjectTgtPairReference = new AtomicReference<>();
    private final AtomicReference<Subject> eternalSubjectReference = new AtomicReference<>();
    private final Callable<Subject> subjectSupplier;
    private final Lock authenticateLock = new ReentrantLock();

    public SubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier) {
        this.implementationName = implementationName;
        this.subjectSupplier = subjectSupplier;
    }

    @Override
    public String getImplementationName() {
        return implementationName;
    }

    @Override
    public Subject getSubject() {
        Subject eternalSubject = eternalSubjectReference.get();
        if (null != eternalSubject) {
            return eternalSubject;
        }
        SubjectTgtPair subjectTgtPair = subjectTgtPairReference.get();
        if (null == subjectTgtPair || subjectTgtPair.isExpired()) {
            authenticateLock.lock();
            try {
                eternalSubject = eternalSubjectReference.get();
                if (null != eternalSubject) {
                    return eternalSubject;
                }
                subjectTgtPair = subjectTgtPairReference.get();
                if (null == subjectTgtPair || subjectTgtPair.isExpired()) {
                    Subject subject = subjectSupplier.call();
                    for (KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class)) {
                        if (ticket.getServer().getName().startsWith("krbtgt")) {
                            subjectTgtPairReference.set(new SubjectTgtPair(ticket, subject));
                            break;
                        }
                    }
                    subjectTgtPair = subjectTgtPairReference.get();
                    if (null == subjectTgtPair) {
                        // isInitiator=false / acceptOnly subjects do not contain a TGT, so there is no expiry time
                        // to drive refresh. Keep that subject permanently to preserve the old JDK accept-only behavior.
                        eternalSubjectReference.set(subject);
                        return subject;
                    }
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw KerberosFailureAnalyzer.wrap("kerberos.login", e);
            } finally {
                authenticateLock.unlock();
            }
        }
        return subjectTgtPair.subject;
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
        Subject subject = getSubject();
        return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, SpnegoProvider.getServerName(url)));
    }

    @Override
    public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
            throws PrivilegedActionException, GSSException, MalformedURLException {
        Subject subject = getSubject();
        return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, SpnegoProvider.createGSSNameForSPN(spn)));
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
        try {
            Thread.sleep(31);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

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

        private boolean isExpired() {
            try {
                synchronized (tgt) {
                    return tgt.getEndTime().before(new Date());
                }
            } catch (Exception e) {
                LOGGER.error("Failed to get Kerberos ticket end time", e);
                return true;
            }
        }
    }
}
