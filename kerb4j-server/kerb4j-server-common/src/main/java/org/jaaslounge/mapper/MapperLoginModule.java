
package org.jaaslounge.mapper;

import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;



import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jaaslounge.AbstractLoginModule;

public class MapperLoginModule extends AbstractLoginModule {

	private LoginContext lc = null;
	
	private Collection mappedGroups = null;
	
	private Object loginContextKey;
	
	private SortedMap roleMaps;
	
	private SortedMap sourceModes;
	
	private SortedMap mappedLoginContextNames;
	
	public void _initialize() {
	    roleMaps = new TreeMap();
	    sourceModes = new TreeMap();
	    mappedLoginContextNames = new TreeMap();
	    for (Iterator itOptions=getOptions().entrySet().iterator(); itOptions.hasNext();) {
	        Map.Entry option = (Map.Entry) itOptions.next();
	        String optionName = option.getKey().toString();
	        if (optionName.startsWith("context.")) {
	            int namePos = optionName.indexOf('.',"context.".length());
	            if (namePos!=-1) {
	                String contextName = optionName.substring("context.".length(),namePos);
	                if (optionName.startsWith("role.source.",namePos+contextName.length())) {
	    	            String roleKey = optionName.substring("role.source.".length()+namePos+contextName.length());
	    	            String sourceRole = option.getValue().toString();
	    	            Object destRole = getOptions().get("context."+contextName+".role.dest."+roleKey);
	    	            Map contextRoleMap = (Map) roleMaps.get(contextName); 
	    	            if (contextRoleMap==null) {
	    	                contextRoleMap = new HashMap();
	    	                roleMaps.put(contextName,contextRoleMap);
	    	            }
	    	            contextRoleMap.put(sourceRole,(destRole==null?"null":destRole));
	    	        }
	                if (optionName.startsWith("name",namePos+contextName.length())) {
	                    String mappedContext = option.getValue().toString();
	                    mappedLoginContextNames.put(contextName,mappedContext);
	                }
	                if (optionName.startsWith("mode",namePos+contextName.length())) {
	                    Integer mappedMode = new Integer(parseMode(option.getValue().toString()));
	                    sourceModes.put(contextName,mappedMode);
	                }
	            }
	        
	        }
	    }
	    if (isDebug()) {
	        System.out.println("["+getClass().getName()+"] mappedLoginContextNames: "+mappedLoginContextNames);
			System.out.println("["+getClass().getName()+"] sourceModes: "+sourceModes);
			System.out.println("["+getClass().getName()+"] roleMaps: "+roleMaps);
	    }
	    
	}
	
	public void authenticate() throws FailedLoginException {
	    mappedGroups=null;
	    contextLoop : for (Iterator it=this.mappedLoginContextNames.keySet().iterator(); it.hasNext();) {
	        loginContextKey = it.next();
		    try {	    		        
		    	lc = new LoginContext(mappedLoginContextNames.get(loginContextKey).toString(), new CallbackHandler() {		        	
					public void handle(Callback[] callbacks) throws IOException,
							UnsupportedCallbackException {
						
						Callback[] mono=new Callback[1];
						for (int i = 0; i < callbacks.length; i++) {
							mono[0]=callbacks[i];
						    if (mono[0] instanceof NameCallback) {
						    	((NameCallback)mono[0]).setName(getUsername());
					 		} else if (mono[0] instanceof PasswordCallback) {
					 			((PasswordCallback)mono[0]).setPassword(getPassword());
					 		
					 	    } else {
					 	    	getCallbackHandler().handle(mono);
					 	    }
						}
					}
		        });		        
		        lc.login();		
		        break contextLoop;
		    } catch (LoginException e) {
		        if (!it.hasNext())
		            throw new FailedLoginException("mapped LoginContext exception : "+e.getMessage());
		    }
	    }
	    
	}

    public Collection getUserGroups() {
        if (mappedGroups==null) {
            mappedGroups=new ArrayList();
            Collection source_principals=lc.getSubject().getPrincipals();
            Map roleMap = (Map) roleMaps.get(loginContextKey);
            if (roleMap==null) {
                roleMap=new HashMap();
                roleMaps.put(loginContextKey,roleMap);
            }
            switch (((Integer)sourceModes.get(loginContextKey)).intValue()) {
    		case JBOSS:
    			// jboss : user, group of roles, group of callerprincipal 
    		    for (java.util.Iterator it=source_principals.iterator();it.hasNext();) {
    		        java.security.Principal principal = (java.security.Principal)it.next();
    		        if (Group.class.isAssignableFrom(principal.getClass())) {
    		            if (principal.getName().equalsIgnoreCase("Roles")) {
    		                // group of roles
    		                Enumeration enumRoles=((Group)principal).members();
    		                while (enumRoles.hasMoreElements()) {
    		                    Principal role = (Principal)enumRoles.nextElement();
    		                    Object mapped_name = roleMap.get(role.getName());
    		        			mappedGroups.add(mapped_name==null?role.getName():mapped_name);
    		                }
    		            }
    		        } 
    		    }    			
    		break;
    		
    		case TOMCAT:
    		case GLASSFISH:
    		default:
    			// tomcat : list of instances of role class & user class
    		    // TODO : diff�rencier le role de l'identit� (utiliser un parametre RoleClass)
    		    for (java.util.Iterator it=source_principals.iterator();it.hasNext();) {
        			String name=((java.security.Principal)it.next()).getName();
        			Object mapped_name = roleMap.get(name);
        			mappedGroups.add(mapped_name==null?name:mapped_name);
        		}
            }
            
        }
        return mappedGroups;
    }
	
}


