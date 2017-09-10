package com.kerb4j.server.tomcat;

import org.apache.catalina.realm.RealmBase;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Defini le realm permettant de gorer des utilisateurs configuras via Active Directory.<br>
 * Ce realm se configure en utilisant les parametres suivants :<ul>
 * <li>domainController : indique l'adresse (IP ou DNS) du controlleur de domaine</li>
 * <li>servicePrincipalName : indique le nom du service pour l'identification aupres de Kerberos</li>
 * <li>servicePassword : indique le mot de passe du service pour l'identification aupres de Kerberos</li>
 * <li>loginModule : indique le nom du login module y utiliser pour la connexion i Kerberos</li>
 * <li>ldapSearchContext : indique le contexte de recherche pour Active Directory : DC=MY,DC=DOMAIN,DC=COM</li>
 * <li>contextFactory : indique la classe permettant de creer le contexte initial</li>
 * <li>stripGroupNames : indique si on veux obtenir les groupes active directory complets (CN=group,OU=organisation,DC=MY,DC=DOMAIN,DC=COM) ou seulement le nom court (group)</li>
 * </ul>
 * @author damien
 */
public class SpnegoRealm extends RealmBase {
	/** cache des associations nom d'utilisateur - principal */
	private Map<String, Principal> realm;

	/**
	 * Initialise le realm
	 */
	public SpnegoRealm() {
		realm = new HashMap();
	}
	
	public String getInfo() {
		return "org.com.kerb4j.server.tomcat.SpnegoRealm/1.0";
	}
	
	protected String getName() {
		return "Spnego Realm";
	}

	protected String getPassword(String princ) {
		return null;
	}

	protected Principal getPrincipal(String princ) {
		SpnegoPrincipal principal = (SpnegoPrincipal) realm.get(princ);
		if (principal == null) {
			principal = new SpnegoPrincipal(princ);
			realm.put(princ, principal);
		}
		return principal;
	}

}
