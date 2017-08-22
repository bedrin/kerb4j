package org.jaaslounge.sso.tomcat.spnego;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jaaslounge.sso.tomcat.Configurator;

/**
 * Permet d'interroger un registre Active Directory pour lire les informations de groupe.
 * On utilise une seule instance de cette classe pour toute l'application (on considère que
 * l'on n'accède pas simultanément à plusieurs registres Active Directory).
 * @author damien
 */
public class ActiveDirectoryReader implements PrivilegedAction {
	private static ActiveDirectoryReader reader;
	private String username;
	private String password;
	private String searchContext;
	private String loginContext;
	private Hashtable options;
	
	private List lastRoles;
	private String searchedName;
	
	/**
	 * Crée et configure l'instance si elle n'est pas déjà créée, retourne cette instance.
	 * @return instance du lecteur Active Directory
	 */
	public static synchronized ActiveDirectoryReader getReader() {
		if (reader == null) {
			reader = new ActiveDirectoryReader();
		}
		return reader;
	}
	
	/**
	 * On interdit l'instanciation ailleurs que par le singleton
	 */
	private ActiveDirectoryReader() {
		Configurator config = Configurator.getConfigurator();
		this.username = config.getServicePrincipalName();
		this.password = config.getServicePassword();
		this.searchContext = config.getLdapSearchContext();
		this.loginContext = config.getLoginContext();
		
		options = new Hashtable();
		options.put(Context.PROVIDER_URL, "ldap://" + config.getDomainController() + ":389");
		options.put(Context.INITIAL_CONTEXT_FACTORY, config.getContextFactory());
		options.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
		options.put("javax.security.sasl.qop", "auth");		
	}
	
	/**
	 * Obtient la liste des rôles pour l'utilisateur indiqué
	 * @param sname nom d'utilisateur recherché
	 * @return liste des groupes associés
	 */
	public synchronized List getRolesForName(String sname) {
		LoginContext context = null;
		try {
			context = new LoginContext(loginContext, new CallbackHandler() {
				public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
					for (int i = 0; i < callbacks.length; i++) {
						// callback for username
						if (callbacks[i] instanceof NameCallback) {
							((NameCallback)callbacks[i]).setName(username);
						// callback for password
						} else if (callbacks[i] instanceof PasswordCallback) {
							((PasswordCallback)callbacks[i]).setPassword(password.toCharArray());
		                } else {
		                	throw new UnsupportedCallbackException(callbacks[i]);
		                }
		            }
				}			
			});
			
			lastRoles = null;
			searchedName = sname;
			context.login();
			Subject.doAs(context.getSubject(), this);
		} catch (LoginException e) {
			e.printStackTrace();
			lastRoles = null;
		}  finally {
			try { 
				if (context != null) {
					context.logout();
				}
			} catch (LoginException e) {}
		}
		return lastRoles;
	}
	
	/**
	 * Effectue la recherche des groupes
	 */
	private void performLookup() {
		boolean stripRoles = Configurator.getConfigurator().isStripGroupNames();
		try {
			lastRoles = new ArrayList();
			DirContext dirContext = new InitialDirContext(options);
			
			SearchControls searchCtls = new SearchControls();
	        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

	        // create filter
	        String searchFilter = "(&(objectClass=user)(userPrincipalName=" + searchedName + "*))";
	        // define returned attribs
	        String returnedAtts[] ={"memberOf"};

	        searchCtls.setReturningAttributes(returnedAtts);

	        // search for objects
	        NamingEnumeration answer = dirContext.search(searchContext, searchFilter,searchCtls);

	        // Loop through the search results
	        while (answer.hasMoreElements()) {
	        	SearchResult sr = (SearchResult) answer.next();

	        	Attributes attrs = sr.getAttributes();
	        	if (attrs != null) {
	        		try {
	        			for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
	        				Attribute attr = (Attribute) ae.next();

			                // enum elements
			                for (NamingEnumeration e = attr.getAll(); e.hasMoreElements();) {
			                	String strElement=e.nextElement().toString();

			                	// save group names into group list
			                	if (stripRoles) {
			                		int ndx = strElement.indexOf("CN=") + 3;
			                		lastRoles.add(strElement.substring(ndx, strElement.indexOf(",", ndx)).trim());
			                	} else {
			                		lastRoles.add(strElement);
			                	}
			                }
	        			}
	        		} catch (NamingException e) {
	        			e.printStackTrace();
	        		}
	        	}
	        }
	        
	        // close the context
	        dirContext.close();
		} catch (NamingException ne) {
			ne.printStackTrace();
			lastRoles = null;
		}
	}
	
	/**
	 * Effectue la récupération des infos à proprement parler
	 */
	public Object run() {
		performLookup();
		return null;
	}

}
