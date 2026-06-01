package com.kerb4j.server.spring.ldap;

import com.kerb4j.client.SpnegoClient;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.security.auth.Subject;
import java.security.PrivilegedAction;
import java.util.Hashtable;
import java.util.List;

/**
 * Implementation of an {@link LdapContextSource} that authenticates with the
 * ldap server using Kerberos.
 * <p>
 * Example usage:
 * <pre>
 *  &lt;bean id=&quot;authorizationContextSource&quot; class=&quot;org.springframework.security.kerberos.ldap.KerberosLdapContextSource&quot;&gt;
 *      &lt;constructor-arg value=&quot;${authentication.ldap.ldapUrl}&quot; /&gt;
 *      &lt;property name=&quot;referral&quot; value=&quot;ignore&quot; /&gt;
 *       &lt;property name=&quot;spnegoClient&quot; ref=&quot;spnegoClient&quot;/&gt;
 *   &lt;/bean&gt;
 *
 *   &lt;sec:ldap-user-service id=&quot;ldapUserService&quot; server-ref=&quot;authorizationContextSource&quot; user-search-filter=&quot;(| (userPrincipalName={0}) (sAMAccountName={0}))&quot;
 *       group-search-filter=&quot;(member={0})&quot; group-role-attribute=&quot;cn&quot; role-prefix=&quot;none&quot; /&gt;
 * </pre>
 *
 * @author Nelson Rodrigues
 * @see SpnegoClient
 */
public class KerberosLdapContextSource extends DefaultSpringSecurityContextSource {

    private SpnegoClient spnegoClient;

    /**
     * Instantiates a new kerberos ldap context source.
     *
     * @param url the url
     */
    public KerberosLdapContextSource(String url) {
        super(url);
    }

    /**
     * Instantiates a new kerberos ldap context source.
     *
     * @param urls   the urls
     * @param baseDn the base dn
     */
    public KerberosLdapContextSource(List<String> urls, String baseDn) {
        super(urls, baseDn);
    }

    @Override
    protected DirContext getDirContextInstance(final Hashtable<String, Object> environment) throws NamingException {
        environment.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
        Subject serviceSubject = spnegoClient.getSubject();
        final NamingException[] suppressedException = new NamingException[]{null};
        DirContext dirContext = Subject.doAs(serviceSubject, (PrivilegedAction<DirContext>) () -> {
            try {
                return KerberosLdapContextSource.super.getDirContextInstance(environment);
            } catch (NamingException e) {
                suppressedException[0] = e;
                return null;
            }
        });
        if (suppressedException[0] != null) {
            throw suppressedException[0];
        }
        return dirContext;
    }

    public SpnegoClient getSpnegoClient() {
        return spnegoClient;
    }

    /**
     * The spnegoClient to get the serviceSubject for LDAP authentication
     *
     * @param spnegoClient the spnegoClient
     */
    public void setSpnegoClient(SpnegoClient spnegoClient) {
        this.spnegoClient = spnegoClient;
    }

}
