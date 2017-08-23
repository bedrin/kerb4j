package org.jaaslounge.sso.websphere.spnego;

import java.io.IOException;
import java.security.Principal;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import jcifs.UniAddress;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;
import jcifs.spnego.Authentication;
import jcifs.spnego.AuthenticationException;
import jcifs.util.Base64;

import com.ibm.websphere.security.WebTrustAssociationException;
import com.ibm.websphere.security.WebTrustAssociationFailedException;
import com.ibm.wsspi.security.tai.TAIResult;
import com.ibm.wsspi.security.tai.TrustAssociationInterceptor;

/**
 * Défini un TAI pour Websphere permettant de réaliser l'authentification de l'utilisateur
 * grâce au protocole SPNEGO. La récupération des rôles se fait de façon indépendante par
 * le réglage du registre utilisateur dans websphere. Le code d'authentification est basé
 * sur le code du filtre de servlet AuthenticationFilter de la bibliothèque jcifs-ext.<br />
 * La configuration du TAI utilise les paramètres suivants :<ul>
 * <li>domainName : nom du domaine</li>
 * <li>domainController : adresse du controleur de domaine</li>
 * <li>servicePrincipalName : nom à utiliser pour identifier le service vers kerberos</li>
 * <li>servicePassword : mot de passe à utiliser pour identifier le service vers kerberos</li>
 * </ul>
 * @author damien
 * @see jcifs.http.AuthenticationFilter pour le filtre de servlet
 */
public class SpnegoTAI implements TrustAssociationInterceptor {
	private static final String TYPE = "Spnego Trust Association Interceptor";
	private static final String VERSION = "1.0";
	
	public static final String HTTP_NEGOTIATE = "Negotiate";
    public static final String HTTP_NTLM = "NTLM";
    public static final String HTTP_BASIC = "Basic";
    private String myDomainController = null;
    private String myDefaultDomain = null;
	
	/**
	 * Libérer les ressources éventuellement allouées par le TAI
	 */
	public void cleanup() { }

	/**
	 * Identifiant du TAI
	 */
	public String getType() {
		return TYPE;
	}

	/**
	 * Version du TAI;
	 */
	public String getVersion() {
		return VERSION;
	}

	/**
	 * Initialise le TAI à partir des propriétés renseignées dans WebSphere
	 * @return 0 en cas de succès. toute autre valeur sinon 
	 */
	public int initialize(Properties props) throws WebTrustAssociationFailedException {
		if (!props.containsKey("domainName") || !props.containsKey("domainController") || !props.containsKey("servicePrincipalName") || !props.containsKey("servicePassword")) return 1; 	// échec
		
		myDefaultDomain = props.getProperty("domainName");
		myDomainController = props.getProperty("domainController");
		System.setProperty("jcifs.smb.client.domain", myDefaultDomain);
		System.setProperty("jcifs.http.domainController", myDomainController);
		System.setProperty("jcifs.spnego.servicePrincipal", props.getProperty("servicePrincipalName"));
		System.setProperty("jcifs.spnego.servicePassword", props.getProperty("servicePassword"));
		return 0;
	}

	/**
	 * Indique si le TAI doit répondre à cette requête
	 */
	public boolean isTargetInterceptor(HttpServletRequest request) throws WebTrustAssociationException {
		return true;
	}

	/**
	 * Que faire en cas d'échec ?
	 * @param clearSession
	 * @param req
	 * @param resp
	 * @throws ServletException
	 * @throws IOException
	 */
    private void fail(boolean clearSession, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (clearSession) {
            HttpSession ssn = req.getSession(false);
            if (ssn != null) ssn.removeAttribute("jcifs.http.principal");
        }
        resp.setHeader("WWW-Authenticate", "Negotiate");
    }
	
    /*private String getIdentifier(String pname) {
    	int ndx = pname.indexOf("@");
    	if (ndx != -1) pname = pname.substring(0, ndx);
    	return pname;
    }*/
    
    /**
     * Réécriture de la méthode Authenticate de la classe Negotiate
     * @param request
     * @param response
     * @return
     * @throws ServletException
     * @throws IOException
     * @see jcifs.http.Negotiate#authenticate(HttpServletRequest, HttpServletResponse)
     */
    private Principal authenticate(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        int index = auth.indexOf(' ');
        String mechanism = auth.substring(0, index);
        byte[] token = Base64.decode(auth.substring(index).trim());  
        Authentication authentication = new Authentication();
        try {
            authentication.process(token);
        } catch (AuthenticationException ex) {
            Throwable cause = ex.getCause();
            if (cause == null) throw new ServletException(ex.getMessage());
            if (cause instanceof IOException) throw (IOException) cause;
            throw new ServletException(ex.getMessage(), ex.getCause());
        }
        byte[] nextToken = authentication.getNextToken();
        if (nextToken != null) {
            auth = Base64.encode(nextToken);
            response.setHeader("WWW-Authenticate", mechanism + " " + auth);
        }
        Principal principal = authentication.getPrincipal();
        return principal;
    }
    
	/**
	 * Négotie l'authentification de l'utilisateur
	 */
	public TAIResult negotiateValidateandEstablishTrust(HttpServletRequest req, HttpServletResponse resp) throws WebTrustAssociationFailedException {
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
                    principal = authenticate(req, resp);
                    if (principal == null) return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
                    req.getSession().setAttribute("jcifs.http.principal",
                            principal);

                    return TAIResult.create(HttpServletResponse.SC_OK, principal.getName());
                }
                UniAddress dc = UniAddress.getByName(myDomainController, true);
                String auth = new String(Base64.decode(msg.substring(6)),
                        "US-ASCII");
                int index = auth.indexOf(':');
                String user = (index != -1) ? auth.substring(0, index) : auth;
                String password = (index != -1) ? auth.substring(index + 1) :
                        "";
                index = user.indexOf('\\');
                if (index == -1) index = user.indexOf('/');
                String domain = (index != -1) ? user.substring(0, index) : myDefaultDomain;
                user = (index != -1) ? user.substring(index + 1) : user;
                principal = new NtlmPasswordAuthentication(domain, user,
                        password);
                SmbSession.logon(dc, (NtlmPasswordAuthentication) principal);
            } catch (Exception e) {
	            throw new WebTrustAssociationFailedException(e.toString());
            }
            HttpSession ssn = req.getSession();
            ssn.setAttribute("jcifs.http.principal", principal);
        } else {
            HttpSession ssn = req.getSession(false);
            if (ssn == null || (principal = (Principal)
                    ssn.getAttribute("jcifs.http.principal")) == null) {
            	try {
            		fail(false, req, resp);
            	} catch (ServletException e) {            		
            	} catch (IOException e) {            		
            	}
                return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }			
		
        if (principal != null) return TAIResult.create(HttpServletResponse.SC_OK, principal.getName());
		return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
	}
}
