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
     * Defines constants and parameter names that are used in the  
     * web.xml file, and HTTP request headers, etc.
     * 
     * <p>
     * This class is primarily used internally or by implementers of 
     * custom http clients and by SpnegoFilterConfig.
     *
     */
    public class Constants {

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
