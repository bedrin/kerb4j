package com.kerb4j.client.kerby;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.spi.JaasTicketCacheSubject;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.util.SpnegoProvider;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
            throw new IllegalStateException("Kerby ticket-cache login requires KRB5CCNAME to point to a FILE ccache");
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
            String name = nameStrings == null || nameStrings.isEmpty()
                    ? principalName.getName()
                    : String.join("/", nameStrings);
            String realm = principalName.getRealm();
            return realm == null || realm.isEmpty() || name.contains("@") ? name : name + "@" + realm;
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
                throw new IllegalStateException("Kerby SPNEGO provider cannot realm-qualify principal '" + principal
                        + "'. Configure java.security.krb5.conf with default_realm or use a realm-qualified principal.");
            }
            validateKdcConfig(client, realm);
            return principal + "@" + realm;
        }

        private static KrbClient createClient() throws KrbException {
            String krb5Config = System.getProperty("java.security.krb5.conf");
            if (krb5Config != null && !krb5Config.isEmpty() && !new File(krb5Config).isFile()) {
                throw new IllegalStateException("Kerby SPNEGO provider cannot read java.security.krb5.conf: "
                        + krb5Config);
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
                throw new IllegalStateException("Kerby SPNEGO provider requires KDC configuration for realm " + realm
                        + ". Add a kdc entry to java.security.krb5.conf or enable DNS KDC lookup.");
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
