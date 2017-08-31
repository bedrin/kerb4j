package org.jaaslounge.sso.tomcat.spnego;

import java.security.Principal;
import java.util.List;

/**
 * Represente une identite Active Directory associte y un ensemble de roles.
 * Les roles sont recuperes y la volve lors du premier appel y hasRole.
 * @author damien
 */
public class SpnegoPrincipal {
	/** reference vers le principal */
	private Principal principal;
	/** liste des roles obtenus */
	private List roles;
	
	/**
	 * Construit une identite
	 * @param principal principal
	 */
	public SpnegoPrincipal(Principal principal) {
		this.principal = principal;
	}
	
	/**
	 * Obtient la reference vers le principal
	 * @return Principal
	 */
	public Principal getPrincipal() {
		return principal;
	}

	
	/**
	 * Permet de savoir si le role indique est contenu dans la liste des roles recuperes.
	 * @param role role recherche
	 * @return vrai si l'utilisateur appartient au role, faux sinon
	 */
	public boolean hasRole(String role) {
		return roles.contains(role);
	}
}