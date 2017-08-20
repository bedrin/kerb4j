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
import com.kerb4j.common.util.Constants;
import com.kerb4j.common.util.SpnegoAuthScheme;
import com.kerb4j.common.util.SpnegoProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
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
        this(loginContext, null, false);
    }
    
    /**
     * Create an instance where the GSSCredential is specified by the parameter 
     * and where the GSSCredential is automatically disposed after use.
     *  
     * @param creds credentials to use
     */
    public SpnegoClient(GSSCredential creds) throws LoginException {
        this(null, creds, true);
    }
    
    /**
     * Create an instance where the GSSCredential is specified by the parameter 
     * and whether the GSSCredential should be disposed after use.
     * 
     * @param loginContext loginContext to use
     * @param creds credentials to use
     * @param dispose true if GSSCredential should be disposed after use
     */
    private SpnegoClient(LoginContext loginContext, GSSCredential creds, boolean dispose) throws LoginException {
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
        return new SpnegoClient(Krb5LoginContext.loginWithUsernameAndPassword(username, password), null, false);
    }

    /**
     * Creates an instance where authentication is done using keytab file
     *
     * @param principal principal
     * @param keyTabLocation keyTabLocation
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithKeyTab(String principal, String keyTabLocation) throws LoginException {
        return new SpnegoClient(Krb5LoginContext.loginWithKeyTab(principal, keyTabLocation), null, false);
    }

    /**
     * Creates an instance where authentication is done using ticket cache
     *
     * @param principal principal
     * @throws LoginException LoginException
     */
    public static SpnegoClient loginWithTicketCache(String principal) throws LoginException {
        return new SpnegoClient(Krb5LoginContext.loginWithTicketCache(principal), null, false);
    }

    public Subject getSubject() {
        return subject.get();
    }

    public SpnegoContext createContext(URL url) throws PrivilegedActionException, GSSException {
        return new SpnegoContext(this, getGSSContext(url));
    }

    /**
     * Opens a communications link to the resource referenced by 
     * this URL, if such a connection has not already been established.
     * 
     * <p>
     * This implementation simply calls this objects 
     * connect(URL, ByteArrayOutputStream) method but passing in a null 
     * for the second argument.
     * </p>
     * 
     * @param url url
     * @return an HttpURLConnection object
     * @throws GSSException  GSSException
     * @throws PrivilegedActionException PrivilegedActionException
     * @throws IOException IOException
     *
     * @see java.net.URLConnection#connect()
     */
    public HttpURLConnection connect(final URL url)
        throws GSSException, PrivilegedActionException, IOException {
        
        return this.connect(url, null);
    }

    /**
     * Opens a communications link to the resource referenced by 
     * this URL, if such a connection has not already been established.
     * 
     * @param url target URL
     * @param dooutput optional message/payload to send to server
     * @return an HttpURLConnection object
     * @throws GSSException GSSException
     * @throws PrivilegedActionException PrivilegedActionException
     * @throws IOException IOException
     *
     * @see java.net.URLConnection#connect()
     */
    public HttpURLConnection connect(final URL url, final ByteArrayOutputStream dooutput)
        throws GSSException, PrivilegedActionException, IOException {

        //assertNotConnected();

        SpnegoContext spnegoContext = createContext(url);
        

            byte[] data = spnegoContext.createToken();

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // TODO : re-factor to support (302) redirects
            conn.setInstanceFollowRedirects(false);

            conn.setRequestProperty(Constants.AUTHZ_HEADER, Constants.NEGOTIATE_HEADER + ' ' + Base64.getEncoder().encodeToString(data));

            conn.connect();

            final SpnegoAuthScheme scheme = SpnegoProvider.getAuthScheme(conn.getHeaderField(Constants.AUTHN_HEADER));
            
            // app servers will not return a WWW-Authenticate on 302, (and 30x...?)
            if (null == scheme) {
                LOGGER.trace("SpnegoProvider.getAuthScheme(...) returned null.");
                
            } else {
                data = scheme.getToken();
    
                if (Constants.NEGOTIATE_HEADER.equalsIgnoreCase(scheme.getScheme())) {
                    spnegoContext.processMutualAuthorization(data, 0, data.length);
                    
                } else {
                    throw new UnsupportedOperationException("Scheme NOT Supported: " 
                            + scheme.getScheme());
                }

            }

        return conn;
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
