/**
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package com.kerb4j.client;

import com.kerb4j.common.jaas.sun.Krb5LoginContext;
import com.kerb4j.common.util.JreVendor;
import com.kerb4j.common.util.LRUCache;
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
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This Class may be used by custom clients as a convenience when connecting 
 * to a protected HTTP server.
 *
 * <p>
 * A krb5.conf is required when using this class. Take a
 * look at the <a href="http://spnego.sourceforge.net" target="_blank">spnego.sourceforge.net</a> 
 * documentation for an example krb5.conf file.
 * Also, you must provide a keytab file, or a username and password, or allowtgtsessionkey.
 * </p>
 *
 *
 * <p>
 * To see a working example and instructions on how to use a keytab, take 
 * a look at the <a href="http://spnego.sourceforge.net/client_keytab.html"
 * target="_blank">creating a client keytab</a> example.
 * </p>
 *
 * @author Darwin V. Felix
 *
 */
public final class SpnegoClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpnegoClient.class);
    private final static LRUCache<AbstractMap.SimpleEntry<String, String>, SpnegoClient> SPNEGO_CLIENT_CACHE = new LRUCache<>(1024);
    private final AtomicReference<SubjectTgtPair> subjectTgtPairReference = new AtomicReference<>();
    private final AtomicReference<Subject> eternalSubjectReference = new AtomicReference<>();
    private final Callable<Subject> subjectSupplier;
    private final Lock authenticateLock = new ReentrantLock();

    /**
     * Creates an instance with provided LoginContext
     *
     * @param loginContextSupplier loginContextSupplier
     */
    private SpnegoClient(final Callable<LoginContext> loginContextSupplier) {

        subjectSupplier = new Callable<Subject>() {
            @Override
            public Subject call() throws Exception {

                LoginContext loginContext = loginContextSupplier.call();

                Subject subject = loginContext.getSubject();

                if (null == subject) try {
                    loginContext.login();
                    subject = loginContext.getSubject();
                } catch (LoginException e) {
                    LOGGER.error(e.getMessage(), e);
                    throw new RuntimeException(e);
                }

                return subject;

            }
        };

    }

    public static void resetCache() {
        synchronized (SPNEGO_CLIENT_CACHE) {
            SPNEGO_CLIENT_CACHE.clear();
        }
    }

    /**
     * Creates an instance where authentication is done using username and password
     *
     * @param username username
     * @param password password
     */
    public static SpnegoClient loginWithUsernamePassword(final String username, final String password) {
        return loginWithUsernamePassword(username, password, false);
    }

    /**
     * Creates an instance where authentication is done using username and password
     *
     * @param username username
     * @param password password
     */
    public static SpnegoClient loginWithUsernamePassword(final String username, final String password, final boolean useCache) {

        if (!useCache) return loginWithUsernamePasswordImpl(username, password);

        AbstractMap.SimpleEntry<String, String> entry = new AbstractMap.SimpleEntry<>(username, password);

        SpnegoClient spnegoClient;

        synchronized (SPNEGO_CLIENT_CACHE) {
            spnegoClient = SPNEGO_CLIENT_CACHE.get(entry);
            if (null == spnegoClient) {
                spnegoClient = loginWithUsernamePasswordImpl(username, password);
                SPNEGO_CLIENT_CACHE.put(entry, spnegoClient);
            }
        }

        return spnegoClient;
    }

    private static SpnegoClient loginWithUsernamePasswordImpl(final String username, final String password) {
        return new SpnegoClient(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                return Krb5LoginContext.loginWithUsernameAndPassword(username, password);
            }
        });
    }

    // TODO: add factory methods with implicit principal name

    /**
     * Creates an instance where authentication is done using keytab file
     *
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     */
    public static SpnegoClient loginWithKeyTab(final String principal, final String keyTabLocation) {
        return loginWithKeyTab(principal, keyTabLocation, false);
    }

    // TODO: add factory methods with implicit principal name

    /**
     * Creates an instance where authentication is done using keytab file
     * Allows customizing underlying isInitiator parameter by using acceptOnly parameter - see description below
     *
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     * @param acceptOnly when set to true, SpnegoClient will work offline and ONLY for accepting new tokens. As a result it doesn't require connection to Kerberos server but cannot request new tokens for other services
     * @since 0.1.3
     */
    public static SpnegoClient loginWithKeyTab(final String principal, final String keyTabLocation, final boolean acceptOnly) {
        return new SpnegoClient(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                return Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
            }
        });
    }

    /**
     * Creates an instance where authentication is done using ticket cache
     *
     * @param principal principal
     */
    public static SpnegoClient loginWithTicketCache(final String principal) {
        return new SpnegoClient(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                return Krb5LoginContext.loginWithTicketCache(principal);
            }
        });
    }

    public static SpnegoClient loginWithContext(final LoginContext loginContext) throws LoginException {
        return loginWithContextSupplier(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                return loginContext;
            }
        });
    }

    public static SpnegoClient loginWithContextSupplier(final Callable<LoginContext> loginContextSupplier) throws LoginException {
        return new SpnegoClient(loginContextSupplier);
    }

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
                        // isInitiator = false  / acceptOnly client
                        eternalSubjectReference.set(subject);
                        return subject;
                    }

                }

            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                authenticateLock.unlock();
            }

        }

        return subjectTgtPair.subject;

    }

    public KerberosKey[] getKerberosKeys() {

        Set<KerberosKey> kerberosKeys = getSubject().getPrivateCredentials(KerberosKey.class);
        if (!kerberosKeys.isEmpty()) {
            return new ArrayList<>(kerberosKeys).toArray(new KerberosKey[kerberosKeys.size()]);
        } else {
            Set<KerberosPrincipal> kerberosPrincipals = getSubject().getPrincipals(KerberosPrincipal.class);
            for (KerberosPrincipal kerberosPrincipal : kerberosPrincipals) {
                Set<KeyTab> keyTabs = getSubject().getPrivateCredentials(KeyTab.class);
                for (KeyTab keyTab : keyTabs) {
                    KerberosKey[] keys = keyTab.getKeys(kerberosPrincipal);
                    if (null != keys && keys.length > 0) return keys;
                }
            }
        }

        return null;

    }

    public SpnegoContext createContext(URL url) throws PrivilegedActionException, GSSException {
        return new SpnegoContext(this, getGSSContext(url));
    }

    public SpnegoContext createContextForSPN(String spn) throws PrivilegedActionException, GSSException, MalformedURLException {
        return new SpnegoContext(this, getGSSContextForSPN(spn));
    }

    public String createAuthroizationHeader(URL url) throws PrivilegedActionException, GSSException, IOException {
        SpnegoContext context = createContext(url);
        try {
            return context.createTokenAsAuthroizationHeader();
        } finally {
            context.close();
        }
    }

    public String createAuthroizationHeaderForSPN(String spn) throws PrivilegedActionException, GSSException, IOException {
        SpnegoContext contextForSPN = createContextForSPN(spn);
        try {
            return contextForSPN.createTokenAsAuthroizationHeader();
        } finally {
            contextForSPN.close();
        }
    }

    public SpnegoContext createAcceptContext() throws PrivilegedActionException {

        return new SpnegoContext(this, Subject.doAs(getSubject(), new PrivilegedExceptionAction<GSSContext>() {
            @Override
            public GSSContext run() throws Exception {

                // IBM JDK only understands indefinite lifetime
                final int credentialLifetime;
                if (JreVendor.IS_IBM_JVM) {
                    credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;
                } else {
                    credentialLifetime = GSSCredential.DEFAULT_LIFETIME;
                }

                GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                        null
                        , credentialLifetime
                        , SpnegoProvider.SUPPORTED_OIDS
                        , GSSCredential.ACCEPT_ONLY); // TODO should it be INIT and ACCEPT ?

                return SpnegoProvider.GSS_MANAGER.createContext(credential);

            }
        }));

    }

    /**
     * Returns a GSSContext for the given SPN with a default lifetime.
     *
     * @param spn
     * @return GSSContext for the given url
     */
    private GSSContext getGSSContextForSPN(String spn) throws GSSException, PrivilegedActionException {
        return getGSSContext(SpnegoProvider.createGSSNameForSPN(spn));
    }

    /**
     * Returns a GSSContext for the given url with a default lifetime.
     *
     * @param url http address
     * @return GSSContext for the given url
     */
    private GSSContext getGSSContext(URL url) throws GSSException, PrivilegedActionException {
        return getGSSContext(SpnegoProvider.getServerName(url));
    }

    private GSSContext getGSSContext(final GSSName gssName) throws GSSException, PrivilegedActionException {

        // TODO: is it still a thing?
        // work-around to GSSContext/AD timestamp vs sequence field replay bug
        try {
            Thread.sleep(31);
        } catch (InterruptedException e) {
            assert true;
        }

        return Subject.doAs(getSubject(), new PrivilegedExceptionAction<GSSContext>() {
            @Override
            public GSSContext run() throws Exception {
                GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                        null
                        , GSSCredential.DEFAULT_LIFETIME
                        , SpnegoProvider.SUPPORTED_OIDS
                        , GSSCredential.INITIATE_ONLY);

                GSSContext context = SpnegoProvider.GSS_MANAGER.createContext(gssName
                        , SpnegoProvider.SPNEGO_OID
                        , credential
                        , GSSContext.DEFAULT_LIFETIME);


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
