package com.kerb4j.client.spi;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import org.ietf.jgss.GSSException;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;

/**
 * Backend used by the public {@link SpnegoClient} facade.
 */
public interface SpnegoClientBackend {

    String getImplementationName();

    Subject getSubject();

    KerberosKey[] getKerberosKeys();

    SpnegoContext createContext(SpnegoClient spnegoClient, URL url) throws PrivilegedActionException, GSSException;

    SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
            throws PrivilegedActionException, GSSException, MalformedURLException;

    SpnegoContext createAcceptContext(SpnegoClient spnegoClient) throws PrivilegedActionException;
}
