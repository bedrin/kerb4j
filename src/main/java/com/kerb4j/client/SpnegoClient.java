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
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.atomic.AtomicReference;

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

    /**
     * Login Context for authenticating client.
     */
    private final LoginContext loginContext;

    private final AtomicReference<Subject> subject; // TODO: handle expiration

    /** 
     * Request credential to be delegated. 
     * Default is false. 
     */
    private transient boolean reqCredDeleg = false;

    /**
     * Creates an instance with provided LoginContext
     * 
     * @param loginContext loginContext
     */
    public SpnegoClient(LoginContext loginContext) throws LoginException {
        this.loginContext = loginContext;

        Subject subject = loginContext.getSubject();
        if (null == subject) {
            loginContext.login();
        }
        this.subject = new AtomicReference<>(subject);
    }

    /**
     * Creates an instance where authentication is done using username and password
     * 
     * @param username username
     * @param password password
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithUsernamePassword(String username, String password) throws LoginException {
        return new SpnegoClient(Krb5LoginContext.loginWithUsernameAndPassword(username, password));
    }

    /**
     * Creates an instance where authentication is done using keytab file
     *
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation) throws LoginException {
        return new SpnegoClient(Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation));
    }

    /**
     * Creates an instance where authentication is done using ticket cache
     *
     * @param principal principal
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithTicketCache(String principal) throws LoginException {
        return new SpnegoClient(Krb5LoginContext.loginWithTicketCache(principal));
    }

    public Subject getSubject() {
        return subject.get();
    }

    public SpnegoContext createContext(URL url) throws PrivilegedActionException, GSSException {
        return new SpnegoContext(this, getGSSContext(url));
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

        return Subject.doAs(this.loginContext.getSubject(), (PrivilegedExceptionAction<GSSContext>) () -> {
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
            context.requestCredDeleg(this.reqCredDeleg);

            return context;

        });


    }

    /**
     * Request that this GSSCredential be allowed for delegation.
     * 
     * @param requestDelegation true to allow/request delegation
     */
    public void requestCredDeleg(final boolean requestDelegation) {
        this.reqCredDeleg = requestDelegation;
    }

}
