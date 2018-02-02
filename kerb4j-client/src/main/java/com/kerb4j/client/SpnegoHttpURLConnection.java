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

import com.kerb4j.common.util.Constants;
import com.kerb4j.common.util.SpnegoAuthScheme;
import com.kerb4j.common.util.SpnegoProvider;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This Class may be used by custom clients as a convenience when connecting 
 * to a protected HTTP server.
 * 
 * <p>
 * This mechanism is an alternative to HTTP Basic Authentication where the 
 * HTTP server does not support Basic Auth but instead has SPNEGO support 
 *
 * <p>
 * A krb5.conf and a login.conf is required when using this class. Take a 
 * look at the <a href="http://spnego.sourceforge.net" target="_blank">spnego.sourceforge.net</a> 
 * documentation for an example krb5.conf file.
 * Also, you must provide a keytab file, or a username and password, or allowtgtsessionkey.
 *
 * <p>
 * Example usage (username/password):
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         System.setProperty("java.security.krb5.conf", "krb5.conf");
 *         System.setProperty("sun.security.krb5.debug", "true");
 *         System.setProperty("java.security.auth.login.config", "login.conf");
 *         
 *         SpnegoHttpURLConnection spnego = null;
 *         
 *         try {
 *             spnego = new SpnegoHttpURLConnection("spnego-client", "dfelix", "myp@s5");
 *             spnego.connect(new URL("http://medusa:8080/index.jsp"));
 *             
 *             System.out.println(spnego.getResponseCode());
 *         
 *         } finally {
 *             if (null != spnego) {
 *                 spnego.disconnect();
 *             }
 *         }
 *     }
 * </pre>
 *
 * <p>
 * Alternatively, if the server supports HTTP Basic Authentication, this Class 
 * is NOT needed and instead you can do something like the following:
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         final String creds = "dfelix:myp@s5";
 *         
 *         final String token = Base64.encodeImpl(creds.getBytes());
 *         
 *         URL url = new URL("http://medusa:8080/index.jsp");
 *         
 *         HttpURLConnection conn = (HttpURLConnection) url.openConnection();
 *         
 *         conn.setRequestProperty(Constants.AUTHZ_HEADER
 *                 , Constants.BASIC_HEADER + " " + token);
 *                 
 *         conn.connect();
 *         
 *         System.out.println("Response Code:" + conn.getResponseCode());
 *     }
 * </pre>
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
public final class SpnegoHttpURLConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpnegoHttpURLConnection.class);
    
    /** GSSContext is not thread-safe. */
    private static final Lock LOCK = new ReentrantLock();

    /**
     * If false, this connection object has not created a communications link to 
     * the specified URL. If true, the communications link has been established.
     */
    private transient boolean connected = false;

    /**
     * Default is GET.
     * 
     * @see java.net.HttpURLConnection#getRequestMethod()
     */
    private transient String requestMethod = "GET";
    
    /**
     * @see java.net.URLConnection#getRequestProperties()
     */
    private final transient Map<String, List<String>> requestProperties = 
        new LinkedHashMap<>();

    /** 
     * Login Context for authenticating client. If username/password 
     * or GSSCredential is provided (in constructor) then this 
     * field will always be null.
     */
    private final transient SpnegoClient spnegoClient;

    /** 
     * Flag to determine if GSSContext has been established. Users of this 
     * class should always check that this field is true before using/trusting 
     * the contents of the response.
     */
    private transient boolean cntxtEstablished = false;

    /** 
     * Ref to HTTP URL Connection object after calling connect method. 
     * Always call spnego.disconnect() when done using this class.
     */
    private transient HttpURLConnection conn = null;

    /**
     * Request credential to be delegated.
     * Default is false.
     */
    private transient boolean reqCredDeleg = false;

    /**
     * Creates an instance where the LoginContext relies on a keytab 
     * file being specified by "java.security.auth.login.config" or 
     * where LoginContext relies on tgtsessionkey.
     * 
     * @param loginModuleName loginModuleName
     * @throws LoginException LoginException
     */
    @Deprecated
    public SpnegoHttpURLConnection(final String loginModuleName) throws LoginException {
        this.spnegoClient = new SpnegoClient(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                try {
                    return new LoginContext(loginModuleName);
                } catch (LoginException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    /**
     * Creates an instance where the LoginContext does not require a keytab
     * file. However, the "java.security.auth.login.config" property must still
     * be set prior to instantiating this object.
     * 
     * @param loginModuleName  loginModuleName
     * @param username username
     * @param password password
     * @throws LoginException LoginException
     */
    @Deprecated
    public SpnegoHttpURLConnection(final String loginModuleName, final String username, final String password)
            throws LoginException {
        this.spnegoClient = new SpnegoClient(new Callable<LoginContext>() {
            @Override
            public LoginContext call() throws Exception {
                try {
                    return new LoginContext(
                            loginModuleName,
                            SpnegoProvider.getUsernameAndPasswordHandler(username, password)
                    );
                } catch (LoginException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    public SpnegoHttpURLConnection(SpnegoClient spnegoClient) {
        this.spnegoClient = spnegoClient;
    }

    /**
     * Throws IllegalStateException if this connection object has not yet created 
     * a communications link to the specified URL.
     */
    private void assertConnected() {
        if (!this.connected) {
            throw new IllegalStateException("Not connected.");
        }
    }

    /**
     * Throws IllegalStateException if this connection object has already created 
     * a communications link to the specified URL.
     */
    private void assertNotConnected() {
        if (this.connected) {
            throw new IllegalStateException("Already connected.");
        }
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

        assertNotConnected();

        SpnegoContext context = spnegoClient.createContext(url);
        if (reqCredDeleg) {
            context.requestCredentialsDelegation();
        }
        
        try {

            this.conn = (HttpURLConnection) url.openConnection();
            this.connected = true;

            final Set<String> keys = this.requestProperties.keySet();
            for (final String key : keys) {
                for (String value : this.requestProperties.get(key)) {
                    this.conn.addRequestProperty(key, value);
                }
            }

            // TODO : re-factor to support (302) redirects
            this.conn.setInstanceFollowRedirects(false);
            this.conn.setRequestMethod(this.requestMethod);

            this.conn.setRequestProperty(Constants.AUTHZ_HEADER, context.createTokenAsAuthroizationHeader());

            if (null != dooutput && dooutput.size() > 0) {
                this.conn.setDoOutput(true);
                dooutput.writeTo(this.conn.getOutputStream());
            }

            this.conn.connect();

            final SpnegoAuthScheme scheme = SpnegoProvider.getAuthScheme(
                    this.conn.getHeaderField(Constants.AUTHN_HEADER));
            
            // app servers will not return a WWW-Authenticate on 302, (and 30x...?)
            if (null == scheme) {
                LOGGER.trace("SpnegoProvider.getAuthScheme(...) returned null.");
                
            } else {
                byte[] data = scheme.getToken();
    
                if (Constants.NEGOTIATE_HEADER.equalsIgnoreCase(scheme.getScheme())) {
                    SpnegoHttpURLConnection.LOCK.lock();
                    try {
                        context.processMutualAuthorization(data, 0, data.length);
                    } finally {
                        SpnegoHttpURLConnection.LOCK.unlock();
                    }
                    
                } else {
                    throw new UnsupportedOperationException("Scheme NOT Supported: " 
                            + scheme.getScheme());
                }

                this.cntxtEstablished = context.isEstablished();
            }
        } finally {
            this.dispose(context);
        }

        return this.conn;
    }

    /**
     * Logout the LoginContext instance, and call dispose() on GSSCredential 
     * if autoDisposeCreds is set to true, and call dispose on the passed-in 
     * GSSContext instance.
     */
    private void dispose(final SpnegoContext context) {
        if (null != context) {
            try {
                SpnegoHttpURLConnection.LOCK.lock();
                try {
                    context.close();
                } finally {
                    SpnegoHttpURLConnection.LOCK.unlock();
                }
            } catch (IOException gsse) {
                LOGGER.error("call to dispose context failed.", gsse);
            }
        }

    }

    /**
     * Logout and clear request properties.
     * 
     * @see java.net.HttpURLConnection#disconnect()
     */
    public void disconnect() {
        this.dispose(null);
        this.requestProperties.clear();
        this.connected = false;
        if (null != this.conn) {
            this.conn.disconnect();
        }
    }

    /**
     * Returns true if GSSContext has been established.
     * 
     * @return true if GSSContext has been established, false otherwise.
     */
    public boolean isContextEstablished() {
        return this.cntxtEstablished;
    }

    /**
     * Internal sanity check to validate not null key/value pairs.
     */
    private void assertKeyValue(final String key, final String value) {
        if (null == key || key.isEmpty()) {
            throw new IllegalArgumentException("key parameter is null or empty");
        }
        if (null == value) {
            throw new IllegalArgumentException("value parameter is null");
        }
    }

    /**
     * Adds an HTTP Request property.
     * 
     * @param key request property name
     * @param value request propery value
     * @see java.net.URLConnection#addRequestProperty(String, String)
     */
    public void addRequestProperty(final String key, final String value) {
        assertNotConnected();
        assertKeyValue(key, value);

        if (this.requestProperties.containsKey(key)) {
            final List<String> val = this.requestProperties.get(key);
            val.add(value);
            this.requestProperties.put(key, val);            
        } else {
            setRequestProperty(key, value);
        }
    }

    /**
     * Sets an HTTP Request property.
     * 
     * @param key request property name
     * @param value request property value
     * @see java.net.URLConnection#setRequestProperty(String, String)
     */
    public void setRequestProperty(final String key, final String value) {
        assertNotConnected();
        assertKeyValue(key, value);

        this.requestProperties.put(key, Arrays.asList(value));
    }
    
    /**
     * Returns an error stream that reads from this open connection.
     * 
     * @return error stream that reads from this open connection
     *
     * @see java.net.HttpURLConnection#getErrorStream()
     * @throws IOException IOException
     */
    public InputStream getErrorStream() throws IOException {
        assertConnected();

        return this.conn.getInputStream();
    }

    /**
     * Get header value at specified index.
     *
     * @param index index
     * @return header value at specified index
     */
    public String getHeaderField(final int index) {
        assertConnected();
        
        return this.conn.getHeaderField(index);
    }
    
    /**
     * Get header value by header name.
     * 
     * @param name name header
     * @return header value
     * @see java.net.HttpURLConnection#getHeaderField(String)
     */
    public String getHeaderField(final String name) {
        assertConnected();

        return this.conn.getHeaderField(name);
    }
    
    /**
     * Get header field key at specified index.
     *
     * @param index index
     * @return header field key at specified index
     */
    public String getHeaderFieldKey(final int index) {
        assertConnected();
        
        return this.conn.getHeaderFieldKey(index);
    }

    /**
     * Returns an input stream that reads from this open connection.
     * 
     * @return input stream that reads from this open connection
     *
     * @see java.net.HttpURLConnection#getInputStream()
     * @throws IOException IOException
     */
    public InputStream getInputStream() throws IOException {
        assertConnected();

        return this.conn.getInputStream();
    }
    
    /**
     * Returns an output stream that writes to this open connection.
     * 
     * @return output stream that writes to this connections
     *
     * @see java.net.HttpURLConnection#getOutputStream()
     * @throws IOException IOException
     */
    public OutputStream getOutputStream() throws IOException {
        assertConnected();
        
        return this.conn.getOutputStream();
    }

    /**
     * Returns HTTP Status code.
     * 
     * @return HTTP Status Code
     *
     * @see java.net.HttpURLConnection#getResponseCode()
     * @throws IOException IOException
     */
    public int getResponseCode() throws IOException {
        assertConnected();

        return this.conn.getResponseCode();
    }

    /**
     * Returns HTTP Status message.
     * 
     * @return HTTP Status Message
     *
     * @see java.net.HttpURLConnection#getResponseMessage()
     * @throws IOException IOException
     */
    public String getResponseMessage() throws IOException {
        assertConnected();

        return this.conn.getResponseMessage();
    }
    
    /**
     * Request that this GSSCredential be allowed for delegation.
     * 
     * @param requestDelegation true to allow/request delegation
     */
    public void requestCredDeleg(final boolean requestDelegation) {
        this.assertNotConnected();
        
        this.reqCredDeleg = requestDelegation;
    }

    /**
     * May override the default GET method.
     * 
     * @param method method
     * 
     * @see java.net.HttpURLConnection#setRequestMethod(String)
     */
    public void setRequestMethod(final String method) {
        assertNotConnected();

        this.requestMethod = method;
    }
}
