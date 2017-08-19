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

package net.sourceforge.spnego;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ietf.jgss.GSSException;

/**
 * Http Servlet Filter that provides <a
 * href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">SPNEGO</a> authentication.
 * It allows servlet containers like Tomcat and JBoss to transparently/silently
 * authenticate HTTP clients like Microsoft Internet Explorer (MSIE).
 * 
 * <p>
 * This feature in MSIE is sometimes referred to as single sign-on and/or 
 * Integrated Windows Authentication. In general, there are at least two 
 * authentication mechanisms that allow an HTTP server and an HTTP client 
 * to achieve single sign-on: <b>NTLM</b> and <b>Kerberos/SPNEGO</b>.
 *
 * <p>
 * <b>NTLM</b><br>
 * MSIE has the ability to negotiate NTLM password hashes over an HTTP session 
 * using Base 64 encoded NTLMSSP messages. This is a staple feature of Microsoft's 
 * Internet Information Server (IIS). Open source libraries exists (ie. jCIFS) that 
 * provide NTLM-based authentication capabilities to Servlet Containers. jCIFS uses 
 * NTLM and Microsoft's Active Directory (AD) to authenticate MSIE clients.
 *
 * <p>
 * <b>{@code SpnegoHttpFilter} does NOT support NTLM (tokens).</b>
 *
 * <p>
 * <b>Kerberos/SPNEGO</b><br>
 * Kerberos is an authentication protocol that is implemented in AD. The protocol 
 * does not negotiate passwords between a client and a server but rather uses tokens 
 * to securely prove/authenticate to one another over an un-secure network.
 *
 * <p>
 * <b>{@code SpnegoHttpFilter} does support Kerberos but through the
 * pseudo-mechanism {@code SPNEGO}</b>.
 * <ul>
 * <li><a href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">Wikipedia: SPNEGO</a></li>
 * <li><a href="http://www.ietf.org/rfc/rfc4178.txt" target="_blank">IETF RFC: 4178</a></li>
 * </ul>
 *
 * <p>
 * <b>Localhost Support</b><br>
 * The Kerberos protocol requires that a service must have a Principal Name (SPN) 
 * specified. However, there are some use-cases where it may not be practical to 
 * specify an SPN (ie. Tomcat running on a developer's machine). The DNS 
 * http://localhost is supported but must be configured in the servlet filter's 
 * init params in the web.xml file. 
 *
 * <p><b>Modifying the web.xml file</b>
 * 
 * <p>Here's an example configuration:
 * 
 * <pre>{@code  <filter>
 *      <filter-name>SpnegoHttpFilter</filter-name>
 *      <filter-class>net.sourceforge.spnego.SpnegoHttpFilter</filter-class>
 *
 *      <init-param>
 *          <param-name>spnego.allow.basic</param-name>
 *          <param-value>true</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.allow.localhost</param-name>
 *          <param-value>true</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.allow.unsecure.basic</param-name>
 *          <param-value>true</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.login.client.module</param-name>
 *          <param-value>spnego-client</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.krb5.conf</param-name>
 *          <param-value>krb5.conf</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.login.conf</param-name>
 *          <param-value>login.conf</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.preauth.username</param-name>
 *          <param-value>Zeus</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.preauth.password</param-name>
 *          <param-value>Zeus_Password</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.login.server.module</param-name>
 *          <param-value>spnego-server</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.prompt.ntlm</param-name>
 *          <param-value>true</param-value>
 *      </init-param>
 *
 *      <init-param>
 *          <param-name>spnego.logger.level</param-name>
 *          <param-value>1</param-value>
 *      </init-param>
 *  </filter>
 *}</pre>
 *
 * <p><b>Example usage on web page</b>
 * 
 * <pre>  &lt;html&gt;
 *  &lt;head&gt;
 *      &lt;title&gt;Hello SPNEGO Example&lt;/title&gt;
 *  &lt;/head&gt;
 *  &lt;body&gt;
 *  Hello &lt;%= request.getRemoteUser() %&gt; !
 *  &lt;/body&gt;
 *  &lt;/html&gt;
 *  </pre>
 *
 * <p>
 * Take a look at the <a href="http://spnego.sourceforge.net/reference_docs.html" 
 * target="_blank">reference docs</a> for other configuration parameters.
 *
 * <p>See more usage examples at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 *
 * @author Darwin V. Felix
 * 
 */
public final class SpnegoHttpFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(Constants.LOGGER_NAME);

    /** Object for performing Basic and SPNEGO authentication. */
    private transient SpnegoAuthenticator authenticator = null;

    public void init(final FilterConfig filterConfig) throws ServletException {

        try {
            // set some System properties
            final SpnegoFilterConfig config = SpnegoFilterConfig.getInstance(filterConfig);
            
            // pre-authenticate
            this.authenticator = new SpnegoAuthenticator(config);
        } catch (final LoginException le) {
            throw new ServletException(le);
        } catch (final GSSException gsse) {
            throw new ServletException(gsse);
        } catch (final PrivilegedActionException pae) {
            throw new ServletException(pae);
        } catch (final FileNotFoundException fnfe) {
            throw new ServletException(fnfe);
        } catch (final URISyntaxException uri) {
            throw new ServletException(uri);
        }
    }

    @Override
    public void destroy() {
        if (null != this.authenticator) {
            this.authenticator.dispose();
            this.authenticator = null;
        }
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response
        , final FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse) response);

        // client/caller principal
        final SpnegoPrincipal principal;
        try {
            principal = this.authenticator.authenticate(httpRequest, spnegoResponse);
        } catch (GSSException gsse) {
            LOGGER.severe("HTTP Authorization Header="
                + httpRequest.getHeader(Constants.AUTHZ_HEADER));
            throw new ServletException(gsse);
        }

        // context/auth loop not yet complete
        if (spnegoResponse.isStatusSet()) {
            return;
        }

        // assert
        if (null == principal) {
            LOGGER.severe("Principal was null.");
            spnegoResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, true);
            return;
        }

        LOGGER.fine("principal=" + principal);

        chain.doFilter(new SpnegoHttpServletRequest(httpRequest, principal), response);
    }
    
    /**
     * Defines constants and parameter names that are used in the  
     * web.xml file, and HTTP request headers, etc.
     * 
     * <p>
     * This class is primarily used internally or by implementers of 
     * custom http clients and by {@link SpnegoFilterConfig}.
     *
     */
    public static final class Constants {

        private Constants() {
            // default private
        }
        
        /** 
         * Servlet init param name in web.xml <b>spnego.allow.basic</b>.
         * 
         * <p>Set this value to {@code true} in web.xml if the filter
         * should allow Basic Authentication.
         * 
         * <p>It is recommended that you only allow Basic Authentication 
         * if you have clients that cannot perform Kerberos authentication. 
         * Also, you should consider requiring SSL/TLS by setting 
         * {@code spnego.allow.unsecure.basic} to {@code false}.
         */
        public static final String ALLOW_BASIC = "spnego.allow.basic";

        /**
         * Servlet init param name in web.xml <b>spnego.allow.delegation</b>.
         * 
         * <p>Set this value to {@code true} if server should support
         * credential delegation requests.
         * 
         * <p>Take a look at the {@link DelegateServletRequest} for more 
         * information about other pre-requisites.
         */
        public static final String ALLOW_DELEGATION = "spnego.allow.delegation";
        
        /**
         * Servlet init param name in web.xml <b>spnego.allow.localhost</b>.
         * 
         * <p>Flag to indicate if requests coming from http://localhost 
         * or http://127.0.0.1 should not be authenticated using 
         * Kerberos.
         * 
         * <p>This feature helps to obviate the requirement of 
         * creating an SPN for developer machines.
         * 
         */
        public static final String ALLOW_LOCALHOST = "spnego.allow.localhost";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.allow.unsecure.basic</b>.
         * 
         * <p>Set this value to {@code false} in web.xml if the filter
         * should reject connections that do not use SSL/TLS.
         */
        public static final String ALLOW_UNSEC_BASIC = "spnego.allow.unsecure.basic";
        
        /** 
         * HTTP Response Header <b>WWW-Authenticate</b>. 
         * 
         * <p>The filter will respond with this header with a value of "Basic" 
         * and/or "Negotiate" (based on web.xml file).
         */
        public static final String AUTHN_HEADER = "WWW-Authenticate";
        
        /** 
         * HTTP Request Header <b>Authorization</b>. 
         * 
         * <p>Clients should send this header where the value is the 
         * authentication token(s).
         */
        public static final String AUTHZ_HEADER = "Authorization";
        
        /** 
         * HTTP Response Header <b>Basic</b>. 
         * 
         * <p>The filter will set this as the value for the "WWW-Authenticate" 
         * header if "Basic" auth is allowed (based on web.xml file).
         */
        public static final String BASIC_HEADER = "Basic";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.client.module</b>. 
         * 
         * <p>The LoginModule name that exists in the login.conf file.
         */
        public static final String CLIENT_MODULE = "spnego.login.client.module";

        /** 
         * Servlet init param name in web.xml <b>spnego.krb5.conf</b>. 
         * 
         * <p>The location of the krb5.conf file. On Windows, this file will 
         * sometimes be named krb5.ini and reside {@code %WINDOWS_ROOT%/krb5.ini}
         * here.
         * 
         * <p>By default, Java looks for the file in these locations and order:
         * <ol>
         * <li>System Property (java.security.krb5.conf)</li>
         * <li>%JAVA_HOME%/lib/security/krb5.conf</li>
         * <li>%WINDOWS_ROOT%/krb5.ini</li>
         * </ol>
         *
         */
        public static final String KRB5_CONF = "spnego.krb5.conf";
        
        /**
         * Specify logging level.

         * <pre>
         * 1 = FINEST
         * 2 = FINER
         * 3 = FINE
         * 4 = CONFIG
         * 5 = INFO
         * 6 = WARNING
         * 7 = SEVERE
         * </pre>
         * 
         */
        static final String LOGGER_LEVEL = "spnego.logger.level";
        
        /**
         * Name of Spnego Logger.
         * 
         * <p>Example: {@code Logger.getLogger(Constants.LOGGER_NAME)}
         */
        static final String LOGGER_NAME = "SpnegoHttpFilter"; 
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.conf</b>. 
         * 
         * <p>The location of the login.conf file.
         */
        public static final String LOGIN_CONF = "spnego.login.conf";
        
        /** 
         * HTTP Response Header <b>Negotiate</b>. 
         * 
         * <p>The filter will set this as the value for the "WWW-Authenticate" 
         * header. Note that the filter may also add another header with 
         * a value of "Basic" (if allowed by the web.xml file).
         */
        public static final String NEGOTIATE_HEADER = "Negotiate";
        
        /**
         * NTLM base64-encoded token start value.
         */
        static final String NTLM_PROLOG = "TlRMTVNT";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.preauth.password</b>. 
         * 
         * <p>Network Domain password. For Windows, this is sometimes known 
         * as the Windows NT password.
         */
        public static final String PREAUTH_PASSWORD = "spnego.preauth.password";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.preauth.username</b>. 
         * 
         * <p>Network Domain username. For Windows, this is sometimes known 
         * as the Windows NT username.
         */
        public static final String PREAUTH_USERNAME = "spnego.preauth.username";
        
        /**
         * If server receives an NTLM token, the filter will return with a 401 
         * and with Basic as the only option (no Negotiate) <b>spnego.prompt.ntlm</b>. 
         */
        public static final String PROMPT_NTLM = "spnego.prompt.ntlm";
        
        /** 
         * Servlet init param name in web.xml <b>spnego.login.server.module</b>. 
         * 
         * <p>The LoginModule name that exists in the login.conf file.
         */
        public static final String SERVER_MODULE = "spnego.login.server.module";
    }
}
