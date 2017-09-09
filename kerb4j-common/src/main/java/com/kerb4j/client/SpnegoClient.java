/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package com.kerb4j.client;

import com.kerb4j.common.jaas.sun.Krb5LoginContext;
import com.kerb4j.common.util.SpnegoProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

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

    private final AtomicReference<SubjectTgtPair> subjectTgtPairReference = new AtomicReference<>();

    private final Supplier<Subject> subjectSupplier;

    private final Lock authenticateLock = new ReentrantLock();

    /**
     * Creates an instance with provided LoginContext
     * 
     * @param loginContextSupplier loginContextSupplier
     */
    protected SpnegoClient(Supplier<LoginContext> loginContextSupplier) {

        subjectSupplier = () -> {

            LoginContext loginContext = loginContextSupplier.get();

            Subject subject = loginContext.getSubject();

            if (null == subject) try {
                loginContext.login();
                subject = loginContext.getSubject();
            } catch (LoginException e) {
                LOGGER.error(e.getMessage(), e);
                throw new RuntimeException(e);
            }

            return subject;

        };

    }

    public Subject getSubject() {

        SubjectTgtPair subjectTgtPair = subjectTgtPairReference.get();

        if (null == subjectTgtPair || subjectTgtPair.isExpired()) {

            authenticateLock.lock();
            try {

                subjectTgtPair = subjectTgtPairReference.get();

                if (null == subjectTgtPair || subjectTgtPair.isExpired()) {

                    Subject subject = subjectSupplier.get();

                    subject.getPrivateCredentials(KerberosTicket.class).stream().
                            filter(ticket -> ticket.getServer().getName().startsWith("krbtgt")).
                            findAny().
                            map(tgt -> new SubjectTgtPair(tgt, subject)).
                            ifPresent(subjectTgtPairReference::set);

                    subjectTgtPair = subjectTgtPairReference.get();

                }

            } finally {
                authenticateLock.unlock();
            }

        }

        return subjectTgtPair.subject;

    }

    private static class SubjectTgtPair {

        private final KerberosTicket tgt;
        private final Subject subject;

        private SubjectTgtPair(KerberosTicket tgt, Subject subject) {
            this.tgt = tgt;
            this.subject = subject;
        }

        private boolean isExpired() {
            return tgt.getEndTime().before(new Date());
        }

    }

    // TODO: add factory methods with implicit principal name

    /**
     * Creates an instance where authentication is done using username and password
     * 
     * @param username username
     * @param password password
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithUsernamePassword(String username, String password) throws LoginException {
        return new SpnegoClient(() -> Krb5LoginContext.loginWithUsernameAndPassword(username, password));
    }

    /**
     * Creates an instance where authentication is done using keytab file
     *
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation) throws LoginException {
        return new SpnegoClient(() -> Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation));
    }

    /**
     * Creates an instance where authentication is done using ticket cache
     *
     * @param principal principal
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithTicketCache(String principal) throws LoginException {
        return new SpnegoClient(() -> Krb5LoginContext.loginWithTicketCache(principal));
    }

    public SpnegoContext createContext(URL url) throws PrivilegedActionException, GSSException {
        return new SpnegoContext(this, getGSSContext(url));
    }

    public SpnegoContext createAcceptContext() throws PrivilegedActionException {

        return new SpnegoContext(this, Subject.doAs(getSubject(), (PrivilegedExceptionAction<GSSContext>) () -> {

            GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                    null
                    , GSSCredential.DEFAULT_LIFETIME
                    , SpnegoProvider.SUPPORTED_OIDS
                    , GSSCredential.ACCEPT_ONLY); // TODO should it be INIT and ACCEPT ?

            return SpnegoProvider.GSS_MANAGER.createContext(credential);

        }));

    }
    
    /**
     * Returns a GSSContext for the given url with a default lifetime.
     *  
     * @param url http address
     * @return GSSContext for the given url
     */
    private GSSContext getGSSContext(final URL url) throws GSSException, PrivilegedActionException {

        // TODO: is it still a thing?
        // work-around to GSSContext/AD timestamp vs sequence field replay bug
        try { Thread.sleep(31); } catch (InterruptedException e) { assert true; }

        return Subject.doAs(getSubject(), (PrivilegedExceptionAction<GSSContext>) () -> {
            GSSCredential credential = SpnegoProvider.GSS_MANAGER.createCredential(
                    null
                    , GSSCredential.DEFAULT_LIFETIME
                    , SpnegoProvider.SUPPORTED_OIDS
                    , GSSCredential.INITIATE_ONLY);

            GSSContext context = SpnegoProvider.GSS_MANAGER.createContext(SpnegoProvider.getServerName(url)
                    , SpnegoProvider.SPNEGO_OID
                    , credential
                    , GSSContext.DEFAULT_LIFETIME);


            context.requestMutualAuth(true);
            context.requestConf(true);
            context.requestInteg(true);
            context.requestReplayDet(true);
            context.requestSequenceDet(true);

            return context;

        });


    }

}
