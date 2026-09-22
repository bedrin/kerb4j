package com.kerb4j.client.kerby;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.spi.JaasTicketCacheSubject;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
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
import org.ietf.jgss.GSSName;
import org.jspecify.annotations.NonNull;

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
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class KerbySpnegoClientProvider implements SpnegoClientProvider {

    public static final String NAME = "apache-kerby";
    private static final Duration DEFAULT_TGT_REFRESH_MARGIN = Duration.ofSeconds(60);

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
            return new ConfiguredSubjectBasedSpnegoClientBackend(NAME + "-accept-only",
                    () -> acceptOnlySubject(principal, new File(keyTabLocation)), true);
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
        return new ConfiguredSubjectBasedSpnegoClientBackend(NAME + "-ticket-cache",
                () -> JaasTicketCacheSubject.login(principal, cache), false);
    }

    private static Subject acceptOnlySubject(String principal, File keyTabFile) {
        KerberosPrincipal kerberosPrincipal = new KerberosPrincipal(principal);
        Set<Principal> principals = new HashSet<>();
        principals.add(kerberosPrincipal);
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add(KeyTab.getInstance(kerberosPrincipal, keyTabFile));
        return new Subject(false, principals, new HashSet<>(), privateCredentials);
    }

    // Bridges provider-specific login modes to the internal constructor without exposing new public API.
    private static class ConfiguredSubjectBasedSpnegoClientBackend extends SubjectBasedSpnegoClientBackend {

        private ConfiguredSubjectBasedSpnegoClientBackend(String implementationName, Callable<Subject> subjectSupplier,
                                                          boolean acceptOnly) {
            super(implementationName, subjectSupplier, acceptOnly);
        }
    }

    static class KerbySpnegoClientBackend extends SubjectBasedSpnegoClientBackend {
        private final KerbyCredentials credentials;

        KerbySpnegoClientBackend(KerbyCredentials credentials) {
            super(NAME, credentials::getTgtSubject, false);
            this.credentials = credentials;
        }

        @Override
        public SpnegoContext createContext(SpnegoClient spnegoClient, URL url)
                throws PrivilegedActionException, GSSException {
            ServiceIdentity serviceIdentity = ServiceIdentity.forUrl(url);
            return createInitiatorContext(spnegoClient, serviceIdentity);
        }

        @Override
        public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
                throws PrivilegedActionException, GSSException, MalformedURLException {
            ServiceIdentity serviceIdentity = ServiceIdentity.forSpn(spn);
            return createInitiatorContext(spnegoClient, serviceIdentity);
        }

        private SpnegoContext createInitiatorContext(SpnegoClient spnegoClient, ServiceIdentity serviceIdentity)
                throws PrivilegedActionException, GSSException {
            ServiceSubject firstServiceSubject = subjectForService(serviceIdentity.servicePrincipal);
            try {
                return createInitiatorContext(spnegoClient, serviceIdentity.gssName, firstServiceSubject.subject);
            } catch (PrivilegedActionException | GSSException firstFailure) {
                if (!isNoCredentialFailure(firstFailure)) {
                    throw firstFailure;
                }

                // Invalidate only the TGT used for this service Subject; a newer cached TGT must survive.
                credentials.invalidateTgtTicket(firstServiceSubject.tgt);
                try {
                    // This retry happens before any token generation and constructs a fresh GSS context.
                    ServiceSubject secondServiceSubject = subjectForService(serviceIdentity.servicePrincipal);
                    return createInitiatorContext(spnegoClient, serviceIdentity.gssName, secondServiceSubject.subject);
                } catch (PrivilegedActionException | GSSException | RuntimeException secondFailure) {
                    if (secondFailure != firstFailure) {
                        secondFailure.addSuppressed(firstFailure);
                    }
                    throw secondFailure;
                }
            }
        }

        private SpnegoContext createInitiatorContext(SpnegoClient spnegoClient, GSSName gssName, Subject subject)
                throws PrivilegedActionException, GSSException {
            return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, gssName));
        }

        private ServiceSubject subjectForService(String servicePrincipal) throws PrivilegedActionException {
            try {
                return credentials.getServiceSubject(servicePrincipal);
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }

        private static boolean isNoCredentialFailure(Throwable failure) {
            // Identity tracking also makes malformed cyclic cause chains safe to inspect.
            Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Throwable cause = failure; cause != null && visited.add(cause); cause = cause.getCause()) {
                if (cause instanceof GSSException && ((GSSException) cause).getMajor() == GSSException.NO_CRED) {
                    return true;
                }
            }
            return false;
        }
    }

    static class KerbyCredentials {
        private final Callable<TgtTicket> tgtRequester;
        private final Clock clock;
        private final Duration tgtRefreshMargin;
        private final Lock lock = new ReentrantLock();
        private TgtTicket tgtTicket;

        private KerbyCredentials(Callable<TgtTicket> tgtRequester) {
            this(tgtRequester, Clock.systemUTC(), DEFAULT_TGT_REFRESH_MARGIN);
        }

        // Package-private clock overloads keep expiry tests deterministic without expanding the public API.
        KerbyCredentials(Callable<TgtTicket> tgtRequester, @NonNull Clock clock) {
            this(tgtRequester, clock, DEFAULT_TGT_REFRESH_MARGIN);
        }

        KerbyCredentials(Callable<TgtTicket> tgtRequester, @NonNull Clock clock,
                         @NonNull Duration tgtRefreshMargin) {
            this.tgtRequester = tgtRequester;
            this.clock = Objects.requireNonNull(clock, "clock");
            this.tgtRefreshMargin = requireNonNegative(tgtRefreshMargin);
        }

        static KerbyCredentials withPassword(String principal, String password) {
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

        private ServiceSubject getServiceSubject(String servicePrincipal) throws Exception {
            TgtTicket tgt = getTgtTicket();
            KrbClient client = createClient();
            SgtTicket sgt = client.requestSgt(tgt, servicePrincipal);
            PrincipalName clientPrincipal = sgt.getClientPrincipal() == null ? tgt.getClientPrincipal() : sgt.getClientPrincipal();
            return new ServiceSubject(subjectWithTickets(clientPrincipal, tgt, sgt), tgt);
        }

        TgtTicket getTgtTicket() throws Exception {
            lock.lock();
            try {
                if (tgtTicket == null || isExpired(tgtTicket, clock, tgtRefreshMargin)) {
                    tgtTicket = tgtRequester.call();
                }
                return tgtTicket;
            } finally {
                lock.unlock();
            }
        }

        void invalidateTgtTicket(TgtTicket failedTgt) {
            lock.lock();
            try {
                // Identity comparison prevents a late failure from evicting a newer TGT.
                if (tgtTicket == failedTgt) {
                    tgtTicket = null;
                }
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
                throw new IllegalStateException("Kerby SPNEGO provider cannot realm-qualify principal '" + principal
                        + "'. Configure java.security.krb5.conf with default_realm or use a realm-qualified principal.");
            }
            validateKdcConfig(client, realm);
            return principal + "@" + realm;
        }

        private static String requiredKerberosRealm(KrbClient client, String principal) {
            String realm = kerberosRealm(client);
            if (realm == null || realm.isEmpty()) {
                throw new IllegalStateException("Kerby SPNEGO provider cannot request an enterprise TGT for '"
                        + principal + "'. Configure java.security.krb5.conf with default_realm.");
            }
            return realm;
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

        private static Duration requireNonNegative(Duration duration) {
            Objects.requireNonNull(duration, "tgtRefreshMargin");
            if (duration.isNegative()) {
                throw new IllegalArgumentException("tgtRefreshMargin must not be negative");
            }
            return duration;
        }

        private static boolean isExpired(TgtTicket tgtTicket, Clock clock, Duration refreshMargin) {
            EncKdcRepPart encKdcRepPart = tgtTicket.getEncKdcRepPart();
            KerberosTime endTime = encKdcRepPart == null ? null : encKdcRepPart.getEndTime();
            return endTime == null || endTime.getTime() <= clock.instant().plus(refreshMargin).toEpochMilli();
        }

    }

    // Couples a service Subject to the exact TGT used to create it for identity-safe recovery.
    private static class ServiceSubject {

        private final Subject subject;
        private final TgtTicket tgt;

        private ServiceSubject(Subject subject, TgtTicket tgt) {
            this.subject = subject;
            this.tgt = tgt;
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
