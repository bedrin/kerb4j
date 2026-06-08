package com.kerb4j.client.kerby;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.spi.JaasTicketCacheSubject;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.exception.KerberosFailureAnalyzer;
import com.kerb4j.common.exception.KerberosFailureCategory;
import com.kerb4j.common.exception.KerberosFailureCode;
import com.kerb4j.common.util.SpnegoProvider;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.impl.DefaultInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.*;
import org.ietf.jgss.GSSException;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class KerbySpnegoClientProvider implements SpnegoClientProvider {

    public static final String NAME = "apache-kerby";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public SpnegoClientBackend loginWithUsernamePassword(String username, String password) {
        KerbyCredentials credentials = KerbyCredentials.withPassword(username, password);
        return new KerbySpnegoClientBackend(credentials);
    }

    @Override
    public SpnegoClientBackend loginWithEnterprisePrincipal(String enterprisePrincipal, String password) {
        KerbyCredentials credentials = KerbyCredentials.withEnterprisePrincipal(enterprisePrincipal, password);
        return new KerbySpnegoClientBackend(credentials);
    }

    @Override
    public SpnegoClientBackend loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) {
        if (acceptOnly) {
            return new SubjectBasedSpnegoClientBackend(NAME + "-accept-only",
                    () -> acceptOnlySubject(principal, new File(keyTabLocation)));
        }
        KerbyCredentials credentials = KerbyCredentials.withKeyTab(principal, new File(keyTabLocation));
        return new KerbySpnegoClientBackend(credentials);
    }

    @Override
    public SpnegoClientBackend loginWithTicketCache(String principal) {
        String cacheName = System.getenv("KRB5CCNAME");
        if (cacheName != null && cacheName.startsWith("FILE:")) {
            cacheName = cacheName.substring("FILE:".length());
        }
        File cache = cacheName == null || cacheName.isEmpty() ? null : new File(cacheName);
        if (cache == null) {
            throw KerberosFailureAnalyzer.explicit(
                    "kerberos.login-with-ticket-cache",
                    KerberosFailureCode.TICKET_CACHE_NOT_FOUND,
                    KerberosFailureCategory.CREDENTIALS,
                    "Kerby ticket-cache login requires KRB5CCNAME to point to a FILE credential cache.",
                    null,
                    "KRB5CCNAME is unset or points to a cache type Kerby cannot read",
                    "Run kinit and set KRB5CCNAME to FILE:/path/to/ccache");
        }
        return new SubjectBasedSpnegoClientBackend(NAME + "-ticket-cache",
                () -> JaasTicketCacheSubject.login(principal, cache));
    }

    private static Subject acceptOnlySubject(String principal, File keyTabFile) {
        KerberosPrincipal kerberosPrincipal = new KerberosPrincipal(principal);
        Set<Principal> principals = new HashSet<>();
        principals.add(kerberosPrincipal);
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add(KeyTab.getInstance(kerberosPrincipal, keyTabFile));
        return new Subject(false, principals, new HashSet<>(), privateCredentials);
    }

    private static class KerbySpnegoClientBackend extends SubjectBasedSpnegoClientBackend {
        private final KerbyCredentials credentials;

        private KerbySpnegoClientBackend(KerbyCredentials credentials) {
            super(NAME, credentials::getTgtSubject);
            this.credentials = credentials;
        }

        @Override
        public SpnegoContext createContext(SpnegoClient spnegoClient, URL url)
                throws PrivilegedActionException, GSSException {
            ServiceIdentity serviceIdentity = ServiceIdentity.forUrl(url);
            Subject subject = subjectForService(serviceIdentity.servicePrincipal);
            return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, serviceIdentity.gssName));
        }

        @Override
        public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
                throws PrivilegedActionException, GSSException, MalformedURLException {
            ServiceIdentity serviceIdentity = ServiceIdentity.forSpn(spn);
            Subject subject = subjectForService(serviceIdentity.servicePrincipal);
            return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, serviceIdentity.gssName));
        }

        private Subject subjectForService(String servicePrincipal) throws PrivilegedActionException {
            try {
                return credentials.getServiceSubject(servicePrincipal);
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
    }

    private static class KerbyCredentials {
        private final Callable<TgtTicket> tgtRequester;
        private final Lock lock = new ReentrantLock();
        private TgtTicket tgtTicket;

        private KerbyCredentials(Callable<TgtTicket> tgtRequester) {
            this.tgtRequester = tgtRequester;
        }

        private static KerbyCredentials withPassword(String principal, String password) {
            return new KerbyCredentials(() -> {
                KrbClient client = createClient();
                return client.requestTgt(realmQualifiedPrincipal(client, principal), password);
            });
        }

        private static KerbyCredentials withEnterprisePrincipal(String enterprisePrincipal, String password) {
            return new KerbyCredentials(() -> {
                if (isBlank(enterprisePrincipal)) {
                    throw new IllegalArgumentException("Enterprise principal must not be blank");
                }
                KrbClient client = createClient();
                String realm = requiredKerberosRealm(client, enterprisePrincipal);
                validateKdcConfig(client, realm);
                EnterpriseInternalKrbClient enterpriseClient = new EnterpriseInternalKrbClient(client.getSetting());
                enterpriseClient.init();
                return enterpriseClient.requestEnterpriseTgt(enterprisePrincipal.trim(), realm, password);
            });
        }

        private static KerbyCredentials withKeyTab(String principal, File keyTabFile) {
            return new KerbyCredentials(() -> {
                KrbClient client = createClient();
                return client.requestTgt(realmQualifiedPrincipal(client, principal), keyTabFile);
            });
        }

        private Subject getTgtSubject() throws Exception {
            TgtTicket tgt = getTgtTicket();
            return subjectWithTickets(tgt.getClientPrincipal(), tgt);
        }

        private Subject getServiceSubject(String servicePrincipal) throws Exception {
            TgtTicket tgt = getTgtTicket();
            KrbClient client = createClient();
            SgtTicket sgt = client.requestSgt(tgt, servicePrincipal);
            PrincipalName clientPrincipal = sgt.getClientPrincipal() == null ? tgt.getClientPrincipal() : sgt.getClientPrincipal();
            return subjectWithTickets(clientPrincipal, tgt, sgt);
        }

        private TgtTicket getTgtTicket() throws Exception {
            lock.lock();
            try {
                if (tgtTicket == null || isExpired(tgtTicket)) {
                    tgtTicket = tgtRequester.call();
                }
                return tgtTicket;
            } finally {
                lock.unlock();
            }
        }

        private static Subject subjectWithTickets(PrincipalName clientPrincipal, KrbTicket... tickets) throws IOException {
            Set<Principal> principals = new HashSet<>();
            principals.add(new KerberosPrincipal(toKerberosPrincipalName(clientPrincipal)));
            Set<Object> privateCredentials = new HashSet<>();
            for (KrbTicket ticket : tickets) {
                privateCredentials.add(toKerberosTicket(ticket, clientPrincipal));
            }
            return new Subject(false, principals, new HashSet<>(), privateCredentials);
        }

        private static KerberosTicket toKerberosTicket(KrbTicket ticket, PrincipalName clientPrincipal) throws IOException {
            EncKdcRepPart encKdcRepPart = ticket.getEncKdcRepPart();
            return new KerberosTicket(
                    ticket.getTicket().encode(),
                    new KerberosPrincipal(toKerberosPrincipalName(clientPrincipal)),
                    new KerberosPrincipal(toKerberosPrincipalName(encKdcRepPart.getSname())),
                    encKdcRepPart.getKey().getKeyData(),
                    encKdcRepPart.getKey().getKeyType().getValue(),
                    toBooleanFlags(encKdcRepPart.getFlags()),
                    toDate(encKdcRepPart.getAuthTime()),
                    toDate(encKdcRepPart.getStartTime()),
                    toDate(encKdcRepPart.getEndTime()),
                    toDate(encKdcRepPart.getRenewTill()),
                    null);
        }

        private static String toKerberosPrincipalName(PrincipalName principalName) {
            List<String> nameStrings = principalName.getNameStrings();
            if (nameStrings == null || nameStrings.isEmpty()) {
                String name = principalName.getName();
                String realm = principalName.getRealm();
                return realm == null || realm.isEmpty() || name.contains("@") ? name : name + "@" + realm;
            }
            String name = joinKerberosPrincipalComponents(nameStrings);
            String realm = principalName.getRealm();
            return realm == null || realm.isEmpty() ? name : name + "@" + realm;
        }

        private static String joinKerberosPrincipalComponents(List<String> nameStrings) {
            StringBuilder name = new StringBuilder();
            for (String nameString : nameStrings) {
                if (name.length() > 0) {
                    name.append('/');
                }
                name.append(escapeKerberosPrincipalComponent(nameString));
            }
            return name.toString();
        }

        private static String escapeKerberosPrincipalComponent(String value) {
            StringBuilder escaped = new StringBuilder(value.length());
            for (int i = 0; i < value.length(); i++) {
                char ch = value.charAt(i);
                if (ch == '\\' || ch == '/' || ch == '@') {
                    escaped.append('\\');
                }
                escaped.append(ch);
            }
            return escaped.toString();
        }

        private static boolean[] toBooleanFlags(TicketFlags ticketFlags) {
            boolean[] flags = new boolean[32];
            if (ticketFlags != null) {
                for (TicketFlag ticketFlag : TicketFlag.values()) {
                    int value = ticketFlag.getValue();
                    if (value >= 0 && value < flags.length) {
                        flags[value] = ticketFlags.isFlagSet(ticketFlag);
                    }
                }
            }
            return flags;
        }

        private static Date toDate(KerberosTime kerberosTime) {
            return kerberosTime == null ? null : new Date(kerberosTime.getTime());
        }

        private static String realmQualifiedPrincipal(KrbClient client, String principal) {
            if (principal.contains("@")) {
                validateKdcConfig(client, principal.substring(principal.indexOf('@') + 1));
                return principal;
            }
            String realm = kerberosRealm(client);
            if (realm == null || realm.isEmpty()) {
                throw KerberosFailureAnalyzer.explicit(
                        "kerberos.realm-qualify-principal",
                        KerberosFailureCode.REALM_NOT_CONFIGURED,
                        KerberosFailureCategory.CONFIGURATION,
                        "Kerby SPNEGO provider cannot realm-qualify principal '" + principal + "'.",
                        null,
                        "krb5.conf has no default_realm and the principal is not realm-qualified",
                        "Configure java.security.krb5.conf with default_realm or use a principal like user@REALM");
            }
            validateKdcConfig(client, realm);
            return principal + "@" + realm;
        }

        private static String requiredKerberosRealm(KrbClient client, String principal) {
            String realm = kerberosRealm(client);
            if (realm == null || realm.isEmpty()) {
                throw KerberosFailureAnalyzer.explicit(
                        "kerberos.login-with-enterprise-principal",
                        KerberosFailureCode.REALM_NOT_CONFIGURED,
                        KerberosFailureCategory.CONFIGURATION,
                        "Kerby SPNEGO provider cannot request an enterprise TGT for '" + principal + "'.",
                        null,
                        "krb5.conf has no default_realm",
                        "Configure java.security.krb5.conf with default_realm");
            }
            return realm;
        }

        private static KrbClient createClient() throws KrbException {
            String krb5Config = System.getProperty("java.security.krb5.conf");
            if (krb5Config != null && !krb5Config.isEmpty() && !new File(krb5Config).isFile()) {
                throw KerberosFailureAnalyzer.explicit(
                        "kerberos.read-krb5-conf",
                        KerberosFailureCode.KRB5_CONFIG_NOT_FOUND,
                        KerberosFailureCategory.CONFIGURATION,
                        "Kerby SPNEGO provider cannot read java.security.krb5.conf: " + krb5Config,
                        null,
                        "The java.security.krb5.conf system property points to a missing or unreadable file",
                        "Set java.security.krb5.conf to an existing krb5.conf path readable by the JVM");
            }
            KrbClient client = krb5Config == null || krb5Config.isEmpty()
                    ? new KrbClient()
                    : new KrbClient(new File(krb5Config));
            client.setAllowUdp(false);
            client.setAllowTcp(true);
            client.init();
            validateConfiguredKdc(client);
            return client;
        }

        private static void validateConfiguredKdc(KrbClient client) {
            String realm = kerberosRealm(client);
            if (realm != null && !realm.isEmpty()) {
                validateKdcConfig(client, realm);
            }
        }

        private static void validateKdcConfig(KrbClient client, String realm) {
            if (isBlank(client.getKrbConfig().getKdcHost()) && !hasRealmKdc(client, realm)
                    && !client.getKrbConfig().getDnsLookUpKdc()) {
                throw KerberosFailureAnalyzer.explicit(
                        "kerberos.find-kdc",
                        KerberosFailureCode.KDC_NOT_FOUND,
                        KerberosFailureCategory.NETWORK,
                        "Kerby SPNEGO provider requires KDC configuration for realm " + realm + ".",
                        null,
                        "No kdc entry exists for the realm and DNS KDC lookup is disabled",
                        "Add a kdc entry to java.security.krb5.conf or enable DNS KDC lookup");
            }
        }

        private static String kerberosRealm(KrbClient client) {
            String realm = client.getKrbConfig().getKdcRealm();
            return isBlank(realm) ? client.getKrbConfig().getDefaultRealm() : realm;
        }

        private static boolean hasRealmKdc(KrbClient client, String realm) {
            try {
                List<Object> kdcs = client.getKrbConfig().getRealmSectionItems(realm, "kdc");
                return kdcs != null && !kdcs.isEmpty();
            } catch (RuntimeException e) {
                return false;
            }
        }

        private static boolean isBlank(String value) {
            return value == null || value.trim().isEmpty();
        }

        private static boolean isExpired(TgtTicket tgtTicket) {
            return tgtTicket.getEncKdcRepPart().getEndTime().lessThan(System.currentTimeMillis());
        }

    }

    private static class EnterpriseInternalKrbClient extends DefaultInternalKrbClient {
        private EnterpriseInternalKrbClient(KrbSetting krbSetting) {
            super(krbSetting);
        }

        private TgtTicket requestEnterpriseTgt(String enterprisePrincipal, String realm, String password)
                throws KrbException {
            KOptions requestOptions = new KOptions();
            requestOptions.add(KrbOption.AS_ENTERPRISE_PN, true);
            requestOptions.add(KrbOption.USE_PASSWD, true);
            requestOptions.add(KrbOption.USER_PASSWD, password);

            PrincipalName clientPrincipal = new PrincipalName(
                    Collections.singletonList(enterprisePrincipal),
                    NameType.NT_ENTERPRISE);
            clientPrincipal.setRealm(realm);

            AsRequestWithPasswd asRequest = new AsRequestWithPasswd(getContext());
            asRequest.setClientPrincipal(clientPrincipal);
            asRequest.setServerPrincipal(KrbUtil.makeTgsPrincipal(realm));
            asRequest.setRequestOptions(requestOptions);
            return doRequestTgt(asRequest);
        }
    }

    private static class ServiceIdentity {
        private final String servicePrincipal;
        private final org.ietf.jgss.GSSName gssName;

        private ServiceIdentity(String servicePrincipal, org.ietf.jgss.GSSName gssName) {
            this.servicePrincipal = servicePrincipal;
            this.gssName = gssName;
        }

        private static ServiceIdentity forUrl(URL url) throws GSSException {
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("Cannot create Kerby SPNEGO context for URL without host: " + url);
            }
            return forSpn("HTTP/" + host);
        }

        private static ServiceIdentity forSpn(String spn) throws GSSException {
            if (spn == null || spn.trim().isEmpty()) {
                throw new IllegalArgumentException("SPN must not be blank");
            }
            String servicePrincipal = spn.trim();
            return new ServiceIdentity(servicePrincipal, SpnegoProvider.createGSSNameForSPN(servicePrincipal));
        }
    }
}
