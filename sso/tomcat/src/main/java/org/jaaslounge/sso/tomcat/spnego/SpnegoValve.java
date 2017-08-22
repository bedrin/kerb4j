package org.jaaslounge.sso.tomcat.spnego;

import java.io.IOException;
import java.security.Principal;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import jcifs.UniAddress;
import jcifs.http.Negotiate;
import jcifs.smb.NtStatus;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbSession;
import jcifs.util.Base64;

import org.apache.catalina.HttpRequest;
import org.apache.catalina.HttpResponse;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.deploy.LoginConfig;
import org.jaaslounge.sso.tomcat.Configurator;

/**
 * Valve permettant de gérer l'authentification d'un utilisateur par SPNEGO
 * dans tomcat. La récupération des rôles ne se fait pas à ce niveau.
 * Le code d'authentification est basé sur le code du filtre de servlet
 * AuthenticationFilter de la bibliothèque jcifs-ext.<br />
 * La configuration de la valve utilise les paramètres :<ul>
 * <li>domainController : indique l'adresse (IP ou DNS) du controlleur de domaine</li>
 * <li>domainName : indique le nom de domaine</li>
 * </ul>
 * @see jcifs.http.AuthenticationFilter pour le filtre de servlet
 * @author damien
 */
public class SpnegoValve extends AuthenticatorBase {
    private static final String HTTP_NEGOTIATE = "Negotiate";
    private static final String HTTP_NTLM = "NTLM";
    private static final String HTTP_BASIC = "Basic";

    // ------ propriétés - permet de configurer la valve depuis la configuration de tomcat
    private String domainController = null;
    private String domainName = null;
    
    private static Logger log = Logger.getLogger(SpnegoValve.class.getName());
    
    /**
     * Obtient l'adresse du controlleur de domaine configuré
     * @return adresse du controlleur de domaine
     */
    public String getDomainController() {
    	if (domainController == null) {
    		domainController = Configurator.getConfigurator().getDomainController();
    	}
    	return domainController;
    }
    
    /**
     * Obtient le nom du domaine configuré
     * @return nom du domaine
     */
    public String getDomainName() {
    	if (domainName == null) {
    		domainName = Configurator.getConfigurator().getDomainName();
    	}
    	return domainName;
    }
    
    /**
     * Configure l'adresse du controlleur de domaine
     * @param domainController adresse du controlleur de domaine
     */
    public void setDomainController(String domainController) {
    	this.domainController = domainController;
    	System.setProperty("jcifs.http.domainController", domainController);
    	Configurator.getConfigurator().setDomainController(domainController);
    	log.info("Using domain controller : " + domainController);
    }    

    /**
     * Configure le nom du domaine
     * @param domainName nom du domaine
     */
    public void setDomainName(String domainName) {
    	this.domainName = domainName;
    	System.setProperty("jcifs.http.domainName", domainName);
    	Configurator.getConfigurator().setDomainName(domainName);
    	log.info("Using domain : " + domainName);
    }       
	
    /**
     * Action réalisée en cas d'echec de l'authentification
     * @param clearSession indique s'il faut vider la session ou non
     * @param req requete
     * @param resp réponse
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
    
    /**
     * Réalise l'authentification de l'utilisateur
     * @see jcifs.http.AuthenticationFilter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
	public boolean authenticate(HttpRequest request, HttpResponse response, LoginConfig config) throws IOException {
		HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        Principal principal = null;
        String authType = null;
        String msg = req.getHeader("Authorization");        
        if (msg != null && (msg.regionMatches(true, 0, "Negotiate ", 0, 10) ||
                msg.regionMatches(true, 0, "NTLM ", 0, 5))) {
            authType = msg.regionMatches(true, 0, "Negotiate ", 0, 10) ?
                    HTTP_NEGOTIATE : msg.regionMatches(true, 0, "NTLM ", 0, 5) ?
                            HTTP_NTLM : HTTP_BASIC;
            try {
                if (HTTP_NEGOTIATE.equals(authType) ||
                        HTTP_NTLM.equals(authType)) {
                    principal = Negotiate.authenticate(req, resp);
                    if (principal == null) return false;
                    req.getSession().setAttribute("jcifs.http.principal",
                            principal);

                    register(request, response, principal, authType, principal.getName(), "");
                    
                    log.fine("Authentifié en tant que " + principal.getName());
                    return true;
                }
                UniAddress dc = UniAddress.getByName(getDomainController(), true);
                String auth = new String(Base64.decode(msg.substring(6)),
                        "US-ASCII");
                int index = auth.indexOf(':');
                String user = (index != -1) ? auth.substring(0, index) : auth;
                String password = (index != -1) ? auth.substring(index + 1) :
                        "";
                index = user.indexOf('\\');
                if (index == -1) index = user.indexOf('/');
                String domain = (index != -1) ? user.substring(0, index) : getDomainName();
                user = (index != -1) ? user.substring(index + 1) : user;
                principal = new NtlmPasswordAuthentication(domain, user,
                        password);
                SmbSession.logon(dc, (NtlmPasswordAuthentication) principal);
            } catch (SmbAuthException sae) {
            	try {
	                fail((sae.getNtStatus() == NtStatus.NT_STATUS_ACCESS_VIOLATION),
	                        req, resp);
            	} catch (ServletException e) { }
                return false;
            } catch (ServletException e) {
			}
            HttpSession ssn = req.getSession();
            ssn.setAttribute("jcifs.http.principal", principal);
        } else {
            HttpSession ssn = req.getSession(false);
            if (ssn == null || (principal = (Principal)
                    ssn.getAttribute("jcifs.http.principal")) == null) {
            	try {
            		fail(false, req, resp);
            	} catch (ServletException e) {}
                return false;
            }
        }	
		
        if (principal == null) return false;
        register(request, response, principal, authType, principal.getName(), "");
		return true;
	}
	
}
