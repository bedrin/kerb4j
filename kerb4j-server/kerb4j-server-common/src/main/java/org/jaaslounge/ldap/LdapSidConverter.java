package org.jaaslounge.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapSidConverter {

    private String directoryUrl;
    private String directoryBase;
    private int directoryTimeout;

    public LdapSidConverter(String directoryUrl, String directoryBase, int directoryTimeout) {
        this.directoryUrl = directoryUrl;
        this.directoryBase = directoryBase;
        this.directoryTimeout = directoryTimeout;
    }

    public List<String> getGroupNames(List<String> sids) throws NamingException {
        List<String> names = null;

        Map<String, Object> environnement = new HashMap<String, Object>();
        environnement.put("java.naming.ldap.attributes.binary", "objectSid");
        KeepAliveLdapConnection ldapConnection = KeepAliveLdapConnection.getConnection(directoryUrl, directoryTimeout, environnement);

        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(new String[]{"sAMAccountName"});
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        StringBuilder filterBuilder = new StringBuilder();
        filterBuilder.append("(&(objectClass=group)(|");
        for(String sid : sids)
            filterBuilder.append("(objectSid=" + sid + ")");
        filterBuilder.append("))");

        names = new ArrayList<String>();
        NamingEnumeration<SearchResult> answer = ldapConnection.search(directoryBase, filterBuilder
                .toString(), searchCtls);
        while(answer.hasMoreElements()) {
            Attributes resultAttrs = ((SearchResult)answer.nextElement()).getAttributes();
            if(resultAttrs != null)
                names.add((String)resultAttrs.get("sAMAccountName").get());
        }

        return names;
    }
}
