package org.jaaslounge.sso.tomcat;

/**
 * Permet de conserver la configuration pour le SSO de manière centralisée
 * @author damien
 */
public class Configurator {
	/** Référence à l'instance du configurateur */
	private static Configurator config = null;
	/** SPN correspondant au service pour kerberos */
	private String servicePrincipalName;
	/** mot de passe pour le SPN précédent */
	private String servicePassword;
	/** adresse du controlleur de domaine */
	private String domainController;
	/** nom de domaine */
	private String domainName;
	/** nom de la classe permettant de créer le contexte de recherche initial */
	private String contextFactory;
	/** identifiant du loginModule à utiliser */
	private String loginContext;
	/** contexte de recherche pour active directory (DC=MYDOMAIN,DC=COM) */
	private String ldapSearchContext;
	/** indique si on utilise des noms de groupe courts ou non */
	private boolean stripGroupNames;
	
	/**
	 * Permet d'obtenir le configurateur conservé en mémoire
	 * @return instance courante du configurateur
	 */
	public static synchronized Configurator getConfigurator() {
		if (config == null) {
			config = new Configurator();
		}
		return config;
	}

	/**
	 * Permet de connaitre la valeur pour le contexte de recherche initial
	 * @return classe pour la création du contexte de recherche initial
	 */
	public String getContextFactory() {
		return contextFactory;
	}

	/**
	 * Permet de connaitre la valeur pour le controleur de domaine
	 * @return adresse du controlleur de domaine
	 */
	public String getDomainController() {
		return domainController;
	}

	/**
	 * Permet de connaitre la valeur pour le nom de domaine
	 * @return nom de domaine
	 */
	public String getDomainName() {
		return domainName;
	}

	/**
	 * Permet de connaitre la valeur pour le critere de recherche dans active directory
	 * @return critere de recherche
	 */
	public String getLdapSearchContext() {
		return ldapSearchContext;
	}

	/**
	 * Permet de connaitre la valeur pour le login module à utiliser
	 * @return nom du login module à utiliser
	 */
	public String getLoginContext() {
		return loginContext;
	}

	/**
	 * Permet de connaitre la valeur pour le mot de passe
	 * @return mot de passe pour se connecter à kerberos
	 */
	public String getServicePassword() {
		return servicePassword;
	}

	/**
	 * Permet de connaître la valeur pour le SPN
	 * @return SPN pour se connecter à kerberos
	 */
	public String getServicePrincipalName() {
		return servicePrincipalName;
	}
	
	/**
	 * Permet de connaître la valeur sur la récupération des noms de groupe
	 * @return vrai si on utilise des noms de groupe courts
	 */
	public boolean isStripGroupNames() {
		return stripGroupNames;
	}

	/**
	 * Permet d'affecter la valeur pour la classe de création du contexte de recherche initial
	 * @param contextFactory valeur à affecter
	 */
	public synchronized void setContextFactory(String contextFactory) {
		this.contextFactory = contextFactory;
	}

	/**
	 * Permet d'affecter la valeur pour l'adresse du controleur de domaine
	 * @param domainController valeur à affecter
	 */
	public synchronized void setDomainController(String domainController) {
		this.domainController = domainController;
	}

	/**
	 * Permet d'affecter la valeur pour le nom de domaine
	 * @param domainName valeur à affecter
	 */
	public synchronized void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	/**
	 * Permet d'affecter la valeur pour le critère de recherche dans active directory
	 * @param ldapSearchContext valeur à affecter
	 */
	public synchronized void setLdapSearchContext(String ldapSearchContext) {
		this.ldapSearchContext = ldapSearchContext;
	}

	/**
	 * Permet d'affecter la valeur pour le nom du login module
	 * @param loginContext valeur à affecter
	 */
	public synchronized void setLoginContext(String loginContext) {
		this.loginContext = loginContext;
	}

	/**
	 * Permet d'affecter la valeur pour le mot de passe de connection vers kerberos
	 * @param servicePassword valeur à affecter
	 */
	public synchronized void setServicePassword(String servicePassword) {
		this.servicePassword = servicePassword;
	}

	/**
	 * Permet d'affecter la valeur pour le SPN pour la connection vers kerberos
	 * @param servicePrincipalName valeur à affecter
	 */
	public synchronized void setServicePrincipalName(String servicePrincipalName) {
		this.servicePrincipalName = servicePrincipalName;
	}
	
	/**
	 * Permet d'affecter la valeur indiquant si on utilise des noms de groupe courts ou non
	 * @param stripGroupNames
	 */
	public synchronized void setStripGroupNames(boolean stripGroupNames) {
		this.stripGroupNames = stripGroupNames;
	}
}
