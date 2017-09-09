package org.jaaslounge.ldap;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class KeepAliveLdapConnection {
    public static final int DEFAULT_TIMEOUT = 600000;

    private static Map<String, KeepAliveLdapConnection> instances = new Hashtable<String, KeepAliveLdapConnection>();

    private Hashtable<Object, Object> environnement;
    private int timeout;

    private Subject subject;
    private DirContext context;
    private Thread closing;

    protected KeepAliveLdapConnection() {
        environnement = new Hashtable<Object, Object>();
        environnement.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environnement.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
        environnement.put("javax.security.auth.useSubjectCredsOnly", "false");
        try {
            LoginContext lc = new LoginContext(System.getProperty("org.jaaslounge.sso.jaas.config"));
            lc.login();
            subject = lc.getSubject();
        } catch(LoginException e) {
            subject = null;
        }
    }

    public static synchronized KeepAliveLdapConnection getConnection(String providerUrl,
            int timeout, Map<String, Object> environnement) {
        KeepAliveLdapConnection instance = instances.get(providerUrl);
        if(instance == null) {
            instance = new KeepAliveLdapConnection();
            instance.environnement.put(Context.PROVIDER_URL, providerUrl);
            if(environnement != null)
                instance.environnement.putAll(environnement);
            instances.put(providerUrl, instance);
        }
        instance.timeout = timeout;
        return instance;
    }

    public synchronized NamingEnumeration<SearchResult> search(final String base,
            final String filter, final SearchControls controls) throws NamingException {
        NamingEnumeration<SearchResult> result = null;
        if(context == null) {
            context = new InitialDirContext(environnement);
        }

        if(closing != null && closing.isAlive())
            closing.interrupt();
        closing = new Closure();
        closing.start();
        try {
            result = (NamingEnumeration<SearchResult>)Subject.doAs(subject,
                    new PrivilegedExceptionAction<NamingEnumeration<SearchResult>>() {
                        public NamingEnumeration<SearchResult> run() throws NamingException {
                            return context.search(base, filter, controls);
                        }
                    });
        } catch(PrivilegedActionException e) {
            throw (NamingException)e.getCause();
        }
        return result;
    }

    private synchronized void disconnect() {
        try {
            context.close();
        } catch(NamingException e) {} finally {
            context = null;
        }
    }

    private class Closure extends Thread {
        public void run() {
            try {
                sleep(timeout);
                disconnect();
            } catch(InterruptedException e) {
                // There's activity, do not disconnect
            }
        }
    }

}