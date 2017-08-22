package org.jaaslounge.sso.tomcat.spnego;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * Représente une identité Active Directory associée à un ensemble de rôles.
 * Les rôles sont récupérés à la volée lors du premier appel à hasRole.
 * @author damien
 */
public class SpnegoPrincipal {
	/** référence vers le principal */
	private Principal principal;
	/** liste des roles obtenus */
	private List roles;
	
	/**
	 * Construit une identité
	 * @param principal
	 */
	public SpnegoPrincipal(Principal principal) {
		this.principal = principal;
	}
	
	/**
	 * Obtient la référence vers le principal
	 * @return
	 */
	public Principal getPrincipal() {
		return principal;
	}
	
	/**
	 * Permet de s'assurer que la liste des rôles Active Directory est bien chargée
	 */
	private void ensureRolesLoaded() {
		if (roles == null) {
			roles = ActiveDirectoryReader.getReader().getRolesForName(principal.getName());
			if (roles == null) roles = new ArrayList();
		}
	}
	
	/**
	 * Permet de savoir si le role indiqué est contenu dans la liste des rôles récupérés.
	 * @param role role recherché
	 * @return vrai si l'utilisateur appartient au role, faux sinon
	 */
	public boolean hasRole(String role) {
		ensureRolesLoaded();
		return roles.contains(role);
	}
}