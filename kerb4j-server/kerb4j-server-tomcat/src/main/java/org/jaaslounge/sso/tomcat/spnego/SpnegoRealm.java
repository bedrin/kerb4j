package org.jaaslounge.sso.tomcat.spnego;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.realm.RealmBase;
import org.jaaslounge.sso.tomcat.Configurator;

/**
 * Défini le realm permettant de gérer des utilisateurs configurés via Active Directory.<br />
 * Ce realm se configure en utilisant les paramètres suivants :<ul>
 * <li>domainController : indique l'adresse (IP ou DNS) du controlleur de domaine</li>
 * <li>servicePrincipalName : indique le nom du service pour l'identification auprès de Kerberos</li>
 * <li>servicePassword : indique le mot de passe du service pour l'identification auprès de Kerberos</li>
 * <li>loginModule : indique le nom du login module à utiliser pour la connexion à Kerberos</li>
 * <li>ldapSearchContext : indique le contexte de recherche pour Active Directory : DC=MY,DC=DOMAIN,DC=COM</li>
 * <li>contextFactory : indique la classe permettant de créer le contexte initial</li>
 * <li>stripGroupNames : indique si on veux obtenir les groupes active directory complets (CN=group,OU=organisation,DC=MY,DC=DOMAIN,DC=COM) ou seulement le nom court (group)</li>
 * </ul>
 * @author damien
 */
public class SpnegoRealm extends RealmBase {
	/** cache des associations nom d'utilisateur - principal */
	private Map realm;
	private Configurator config;
	
    // ------ propriétés - permet de configurer le realm depuis la configuration de tomcat	
	public void setContextFactory(String contextFactory) {
		config.setContextFactory(contextFactory);
	}
	public void setDomainController(String domainController) {
		config.setDomainController(domainController);
	}
	public void setLdapSearchContext(String ldapSearchContext) {
		config.setLdapSearchContext(ldapSearchContext);
	}
	public void setLoginModule(String loginModule) {
		config.setLoginContext(loginModule);
	}
	public void setServicePassword(String servicePassword) {
		config.setServicePassword(servicePassword);
	}
	public void setServicePrincipalName(String servicePrincipalName) {
		config.setServicePrincipalName(servicePrincipalName);
	}
	public void setStripGroupNames(boolean stripGroupNames) {
		config.setStripGroupNames(stripGroupNames);
	}
	
	public String getDomainController() {
		return config.getDomainController();
	}	
	public String getServicePrincipalName() {
		return config.getServicePrincipalName();
	}
	public String getServicePassword() {
		return config.getServicePassword();
	}
	public String getLoginModule() {
		return config.getLoginContext();
	}
	public String getLdapSearchContext() {
		return config.getLdapSearchContext();
	}
	public String getContextFactory() {
		return config.getContextFactory();
	}
	public boolean isStripGroupNames() {
		return config.isStripGroupNames();
	}

	/**
	 * Initialise le realm
	 */
	public SpnegoRealm() {
		realm = new HashMap();
		config = Configurator.getConfigurator();
	}
	
	public String getInfo() {
		return "org.jaaslounge.sso.tomcat.spnego.SpnegoRealm/1.0";
	}
	
	protected String getName() {
		return "Spnego Realm";
	}

	protected String getPassword(String princ) {
		return null;
	}

	protected Principal getPrincipal(String princ) {
		SpnegoPrincipal principal = (SpnegoPrincipal) realm.get(princ);
		if (principal != null) {
			return principal.getPrincipal();
		}
		return null;
	}
	
	public boolean hasRole(Principal princ, String role) {
		String pname = princ.getName();
		SpnegoPrincipal principal = (SpnegoPrincipal) realm.get(pname);
		if (principal == null) {
			principal = new SpnegoPrincipal(princ);
			realm.put(pname, principal);
		}		
		return principal.hasRole(role);
	}
}
