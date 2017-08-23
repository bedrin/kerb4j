package org.jaaslounge.sso.tomcat.spnego;

import java.security.Principal;
import java.util.ArrayList;
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
	 * @param principal
	 */
	public SpnegoPrincipal(Principal principal) {
		this.principal = principal;
	}
	
	/**
	 * Obtient la reference vers le principal
	 * @return
	 */
	public Principal getPrincipal() {
		return principal;
	}
	
	/**
	 * Permet de s'assurer que la liste des r�les Active Directory est bien charg�e
	 */
	private void ensureRolesLoaded() {
		if (roles == null) {
			roles = ActiveDirectoryReader.getReader().getRolesForName(principal.getName());
			if (roles == null) roles = new ArrayList();
		}
	}
	
	/**
	 * Permet de savoir si le role indique est contenu dans la liste des roles recuperes.
	 * @param role role recherche
	 * @return vrai si l'utilisateur appartient au role, faux sinon
	 */
	public boolean hasRole(String role) {
		ensureRolesLoaded();
		return roles.contains(role);
	}
}