package org.jaaslounge;

import java.security.Principal;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * Abstract class on top of all JaasLounge Login Modules. This class is responsible of holding
 * server specific and common behaviors.
 * 
 * @author Laurent RUAUD
 * @author Kevin WHITE
 * @author Thomas VILLEGER
 * @author Jerome PETIT
 */
public abstract class AbstractLoginModule implements LoginModule, Authenticator {

    private static Logger LOG = Logger.getLogger(AbstractLoginModule.class.getName());

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, ?> sharedState;
    private Map<String, ?> options;

    // configurable options
    private boolean debug = false;

    protected static final int TOMCAT = 0;
    protected static final int JBOSS = 1;
    protected static final int GLASSFISH = 2;
    protected static final int WEBSPHERE = 3;
    protected static final int JETTY = 4;
    private int mode;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    // username and password
    private String username;
    private char[] password;

    // principals and credentials
    private Set<Principal> principals = new java.util.HashSet<Principal>();
    private Set<Object> publicCredentials = new java.util.HashSet<Object>();
    private Set<Object> privateCredentials = new java.util.HashSet<Object>();

    protected abstract void _initialize();

    protected int parseMode(String modeName) {
        if("jboss".equalsIgnoreCase(modeName))
            return JBOSS;
        else if("tomcat".equalsIgnoreCase(modeName))
            return TOMCAT;
        else if("glassfish".equalsIgnoreCase(modeName))
            return GLASSFISH;
        else if("websphere".equalsIgnoreCase(modeName))
            return WEBSPHERE;
        else if("jetty".equalsIgnoreCase(modeName))
            return JETTY;
        else
            return TOMCAT;
    }

    /**
     * {@inheritDoc}
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		debug = "true".equalsIgnoreCase((String) options.get("debug"));

		String modeName = (String) (getOptions().get("mode"));
		LOG.fine("mode: " + modeName);
		mode = parseMode(modeName);

		_initialize();
	}

    /**
     * {@inheritDoc}
     */
    public boolean login() throws LoginException {
        if(callbackHandler == null)
            throw new LoginException(
                    "Error: no CallbackHandler available to garner authentication information from the user");

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("[" + getClass().getName() + "] username: ");
        callbacks[1] = new PasswordCallback("[" + getClass().getName() + "] password: ", false);

        try {
            callbackHandler.handle(callbacks);
            username = ((NameCallback)callbacks[0]).getName();
            char[] tmpPassword = ((PasswordCallback)callbacks[1]).getPassword();
            if(tmpPassword == null) {
                // treat a NULL password as an empty password
                tmpPassword = new char[0];
            }
            password = new char[tmpPassword.length];
            System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
            ((PasswordCallback)callbacks[1]).clearPassword();

        } catch(java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch(UnsupportedCallbackException uce) {
            throw new LoginException("Error: " + uce.getCallback().toString()
                    + " not available to garner authentication information from the user");
        }

        LOG.fine("user entered username: " + username);
        LOG.fine("user entered password: ***"/* +new String(password) */);

        try {
            authenticate();
            succeeded = true;

            LOG.fine("authentication succeeded");

            return true;
        } catch(FailedLoginException e) {
            LOG.fine("authentication failed :");
            if(debug)
                e.printStackTrace(System.out);

            succeeded = false;
            username = null;
            for(int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
            throw e;
        } catch(Exception e) {
            LOG.fine("authentication failed");
            if(debug)
                e.printStackTrace(System.out);

            succeeded = false;
            username = null;
            for(int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
            throw new FailedLoginException(e.getMessage());
        }
    }

    public void setPrincipalsAndCredentials() {
        UserPrincipal user = new UserPrincipal(getUsername());
        getPrincipals().add(user);
        Collection groups = getUserGroups();

        switch (getMode()) {
        case JBOSS:
        case JETTY:
            // jboss : user, group of roles, group of callerprincipal
            // Jetty and jboss are the same, but the name of the GroupPrincipal
            // they expect is different.
            GroupPrincipal groupRoles = new GroupPrincipal(getMode() == JBOSS ? "Roles"
                    : "__roles__");
            // GroupPrincipal groupCallerPrincipal=new
            // GroupPrincipal("CallerPrincipal");
            for(Iterator itGroups = groups.iterator(); itGroups.hasNext();) {
                String groupName = itGroups.next().toString();
                UserPrincipal role = new UserPrincipal(groupName);
                groupRoles.addMember(role);
                LOG.fine("role : [" + groupName + "]");
                // groupCallerPrincipal.addMember(role);
            }
            getPrincipals().add(groupRoles);
            // getPrincipals().add(groupCallerPrincipal);
            break;

        case TOMCAT:
        case GLASSFISH:
        case WEBSPHERE:
        default:
            // tomcat : list of instances of role class & user class
            for(Iterator itGroups = groups.iterator(); itGroups.hasNext();) {
                String groupName = itGroups.next().toString();
                GroupPrincipal group = new GroupPrincipal(groupName);
                getPrincipals().add(group);
                LOG.fine("role : [" + groupName + "]");
            }
        }
    }

    public abstract Collection getUserGroups();

    /**
     * {@inheritDoc}
     */
    public boolean commit() throws LoginException {
        return _commit();
    }

    private boolean _commit() throws LoginException {
        if(succeeded == false) {
            return false;
        } else {
            final Subject s = subject;
            java.security.AccessController.doPrivileged(new java.security.PrivilegedAction() {
                public Object run() {
                    setPrincipalsAndCredentials();
                    principals.removeAll(s.getPrincipals());
                    // TODO : voir pb ajout de collection de role au
                    // lieu de fusion
                    // corriger eventuellement � l'aide de equals
                    s.getPrincipals().addAll(principals);
                    publicCredentials.removeAll(s.getPublicCredentials());
                    s.getPublicCredentials().addAll(publicCredentials);
                    privateCredentials.removeAll(s.getPrivateCredentials());
                    s.getPrivateCredentials().addAll(privateCredentials);
                    return null;
                }
            });

            LOG.fine("Principals & credentials set for Subject");

            // in any case, clean out state
            username = null;
            for(int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;

            commitSucceeded = true;
            return true;
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean abort() throws LoginException {
        if(succeeded == false) {
            return false;
        } else if(succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
            username = null;
            if(password != null) {
                for(int i = 0; i < password.length; i++)
                    password[i] = ' ';
                password = null;
            }
            principals.clear();
            privateCredentials.clear();
            publicCredentials.clear();
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public boolean logout() throws LoginException {
        final Subject s = subject;
        java.security.AccessController.doPrivileged(new java.security.PrivilegedAction() {
            public Object run() {
                s.getPrincipals().removeAll(principals);
                s.getPrivateCredentials().removeAll(privateCredentials);
                s.getPublicCredentials().removeAll(publicCredentials);
                return null;
            }
        });

        succeeded = false;
        commitSucceeded = false;
        username = null;
        if(password != null) {
            for(int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
        }
        principals.clear();
        privateCredentials.clear();
        publicCredentials.clear();
        return true;
    }

    /**
     * @return Returns the callbackHandler.
     */
    protected CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    /**
     * @return Returns the debug.
     */
    protected boolean isDebug() {
        return debug;
    }

    /**
     * @return Returns the options.
     */
    protected Map getOptions() {
        return options;
    }

    /**
     * @return Returns the password.
     */
    protected char[] getPassword() {
        return password;
    }

    /**
     * @return Returns the sharedState.
     */
    protected Map getSharedState() {
        return sharedState;
    }

    /**
     * @return Returns the principals.
     */
    protected Set getPrincipals() {
        return principals;
    }

    /**
     * @return Returns the privateCredentials.
     */
    protected Set getPrivateCredentials() {
        return privateCredentials;
    }

    /**
     * @return Returns the publicCredentials.
     */
    protected Set getPublicCredentials() {
        return publicCredentials;
    }

    /**
     * @return Returns the username.
     */
    protected String getUsername() {
        return username;
    }

    /**
     * @return Returns the subject.
     */
    protected Subject getSubject() {
        return subject;
    }

    /**
     * @return Returns the mode.
     */
    public int getMode() {
        return mode;
    }
}
