package com.kerb4j.server.tomcat;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.pac.Pac;
import com.kerb4j.server.marshall.pac.PacLogonInfo;
import com.kerb4j.server.marshall.pac.PacSid;
import com.kerb4j.server.marshall.spnego.SpnegoInitToken;
import com.kerb4j.server.marshall.spnego.SpnegoKerberosMechToken;
import com.kerb4j.common.util.Constants;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.codec.binary.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;

/**
 * Valve permettant de gerer l'authentification d'un utilisateur par SPNEGO
 * dans tomcat. La recuperation des roles ne se fait pas y ce niveau.
 * Le code d'authentification est basw sur le code du filtre de servlet
 * AuthenticationFilter de la bibliotheque jcifs-ext.<br>
 * La configuration de la valve utilise les parametres :<ul>
 * <li>domainController : indique l'adresse (IP ou DNS) du controlleur de domaine</li>
 * <li>domainName : indique le nom de domaine</li>
 * </ul>
 * @author damien
 */
public class SpnegoAuthenticator extends AuthenticatorBase {

    private static final Log log = LogFactory.getLog(SpnegoAuthenticator.class);


    private static final String HTTP_NEGOTIATE = "Negotiate";
    private static final String HTTP_NTLM = "NTLM";
    private static final String HTTP_BASIC = "Basic";

    private SpnegoClient spnegoClient;

    // ------ proprietes - permet de configurer la valve depuis la configuration de tomcat
    private String keyTab = null;
    private String principalName = null;

    public String getKeyTab() {
        return keyTab;
    }

    public void setKeyTab(String keyTab) {
        this.keyTab = keyTab;
        log.info("Using keytab : " + principalName);
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
        log.info("Using principal name : " + principalName);
    }


    private boolean storeDelegatedCredential = true;
    public boolean isStoreDelegatedCredential() {
        return storeDelegatedCredential;
    }
    public void setStoreDelegatedCredential(
            boolean storeDelegatedCredential) {
        this.storeDelegatedCredential = storeDelegatedCredential;
    }

    private boolean applyJava8u40Fix = true;
    public boolean getApplyJava8u40Fix() {
        return applyJava8u40Fix;
    }
    public void setApplyJava8u40Fix(boolean applyJava8u40Fix) {
        this.applyJava8u40Fix = applyJava8u40Fix;
    }

    @Override
    protected void initInternal() throws LifecycleException {
        super.initInternal();

        try {
            spnegoClient = SpnegoClient.loginWithKeyTab(principalName, keyTab);
        } catch (Exception e) {
            throw new LifecycleException(e);
        }

    }

    @Override
    protected String getAuthMethod() {
        return HTTP_NEGOTIATE.toUpperCase(); // TODO: what does it mean ? should it be "SPNEGO" ?
    }
	
    /**
     * Action realisee en cas d'echec de l'authentification
     * @param clearSession indique s'il faut vider la session ou non
     * @param req requete
     * @param resp reponse
     * @throws ServletException
     * @throws IOException
     */
    private void fail(boolean clearSession, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	if (clearSession) {
            HttpSession ssn = req.getSession(false);
            if (ssn != null) ssn.removeAttribute("jcifs.http.principal");
        }
        resp.addHeader("WWW-Authenticate", "Negotiate");
        resp.addHeader("WWW-Authenticate", "NTLM");
        
        resp.setHeader("Connection", "close");
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        resp.flushBuffer();
    }

    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response)
            throws IOException {

        if (checkForCachedAuthentication(request, response, true)) {
            return true;
        }

        MessageBytes authorization =
                request.getCoyoteRequest().getMimeHeaders()
                        .getValue("authorization");

        if (authorization == null) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("authenticator.noAuthHeader"));
            }
            response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        authorization.toBytes();
        ByteChunk authorizationBC = authorization.getByteChunk();

        if (!authorizationBC.startsWithIgnoreCase("negotiate ", 0)) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString(
                        "spnegoAuthenticator.authHeaderNotNego"));
            }
            response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        authorizationBC.setOffset(authorizationBC.getOffset() + 10);

        byte[] decoded = Base64.decodeBase64(authorizationBC.getBuffer(),
                authorizationBC.getOffset(),
                authorizationBC.getLength());

        if (getApplyJava8u40Fix()) {
            org.apache.catalina.authenticator.SpnegoAuthenticator.SpnegoTokenFixer.fix(decoded);
        }

        if (decoded.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString(
                        "spnegoAuthenticator.authHeaderNoToken"));
            }
            response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        SpnegoContext acceptContext = null;
        Principal principal = null;
        byte[] outToken;

        try {

            acceptContext = spnegoClient.createAcceptContext();
            outToken = acceptContext.acceptToken(decoded);

            if (outToken == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString(
                            "spnegoAuthenticator.ticketValidateFail"));
                }
                // Start again
                response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return false;
            }

            Subject subject = spnegoClient.getSubject();

            try {
                SpnegoInitToken spnegoInitToken = new SpnegoInitToken(decoded);
                SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();
                Pac pac = spnegoKerberosMechToken.getPac(spnegoClient.getKerberosKeys());

                if (null != pac) {
                    PacLogonInfo logonInfo = pac.getLogonInfo();
                    PacSid[] groupSids = logonInfo.getGroupSids();
                    List<String> roles = new ArrayList<>(groupSids.length);
                    for (PacSid pacSid : groupSids) {
                        roles.add(pacSid.toHumanReadableString());
                    }
                    principal = new SpnegoPrincipal(acceptContext.getSrcName().toString(), roles);
                }

            } catch (Kerb4JException | KrbException e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("spnegoAuthenticator.ticketValidateFail"), e);
                }
                response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return false;
            }

            if (null == principal) {
                GSSContext gssContext = acceptContext.getGSSContext();

                // TODO: check realm call?
                principal = Subject.doAs(subject, new org.apache.catalina.authenticator.SpnegoAuthenticator.AuthenticateAction(
                        context.getRealm(), gssContext, storeDelegatedCredential
                ));
            }

        } catch (GSSException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("spnegoAuthenticator.ticketValidateFail"), e);
            }
            response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        } catch (PrivilegedActionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof GSSException) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("spnegoAuthenticator.serviceLoginFail"), e);
                }
            } else {
                log.error(sm.getString("spnegoAuthenticator.serviceLoginFail"), e);
            }
            response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        } finally {
            if (acceptContext != null) {
                try {
                    acceptContext.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }

        // Send response token on success and failure
        response.setHeader(AUTH_HEADER_NAME, Constants.NEGOTIATE_HEADER + " "
                + Base64.encodeBase64String(outToken));

        if (principal != null) {
            register(request, response, principal, HTTP_NEGOTIATE.toUpperCase(), // TODO: what does it mean ? should it be "SPNEGO" ?,
                    principal.getName(), null);

            // TODO: do we need code below?

            /*Pattern p = noKeepAliveUserAgents;
            if (p != null) {
                MessageBytes ua =
                        request.getCoyoteRequest().getMimeHeaders().getValue(
                                "user-agent");
                if (ua != null && p.matcher(ua.toString()).matches()) {
                    response.setHeader("Connection", "close");
                }
            }*/
            return true;
        }

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return false;

	}
	
}
