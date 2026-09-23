package com.kerb4j.client.kerby;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.client.spi.JaasTicketCacheSubject;
import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SpnegoClientProvider;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import com.kerb4j.common.util.SpnegoProvider;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbErrorException;
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
import org.jspecify.annotations.Nullable;

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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class KerbySpnegoClientProvider implements SpnegoClientProvider {

    public static final String NAME = "apache-kerby";
    private static final Duration DEFAULT_TGT_REFRESH_MARGIN = Duration.ofSeconds(60);
    private static final Duration REFRESH_FAILURE_COOLDOWN = Duration.ofSeconds(1);
    private static final Duration MIN_PROACTIVE_RETRY_DELAY = Duration.ofSeconds(1);
    private static final Duration MAX_PROACTIVE_RETRY_DELAY = Duration.ofSeconds(30);

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
            ContextAttempt firstAttempt = new ContextAttempt();
            try {
                return createInitiatorContext(spnegoClient, serviceIdentity, firstAttempt);
            } catch (PrivilegedActionException | GSSException firstFailure) {
                if (!isCredentialFailure(firstFailure) || firstAttempt.tgt == null) {
                    throw firstFailure;
                }

                // Invalidate only the TGT used for this service Subject; a newer cached TGT must survive.
                credentials.invalidateTgtTicket(firstAttempt.tgt);
                try {
                    // The whole TGT/TGS/GSS attempt is repeated before any token generation.
                    return createInitiatorContext(spnegoClient, serviceIdentity, new ContextAttempt());
                } catch (PrivilegedActionException | GSSException | RuntimeException secondFailure) {
                    if (secondFailure != firstFailure) {
                        secondFailure.addSuppressed(firstFailure);
                    }
                    throw secondFailure;
                }
            }
        }

        private SpnegoContext createInitiatorContext(SpnegoClient spnegoClient, ServiceIdentity serviceIdentity,
                                                     ContextAttempt attempt)
                throws PrivilegedActionException, GSSException {
            try {
                attempt.tgt = credentials.getTgtTicket();
                Subject subject = getServiceSubject(attempt.tgt, serviceIdentity.servicePrincipal);
                return new SpnegoContext(spnegoClient, subject, getGSSContext(subject, serviceIdentity.gssName));
            } catch (PrivilegedActionException | GSSException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }

        protected Subject getServiceSubject(TgtTicket tgt, String servicePrincipal) throws Exception {
            return credentials.getServiceSubject(tgt, servicePrincipal);
        }

        private static boolean isCredentialFailure(Throwable failure) {
            // Identity tracking also makes malformed cyclic cause chains safe to inspect.
            Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Throwable cause = failure; cause != null && visited.add(cause); cause = cause.getCause()) {
                if (cause instanceof GSSException && ((GSSException) cause).getMajor() == GSSException.NO_CRED) {
                    return true;
                }
                KrbErrorCode errorCode = krbErrorCode(cause);
                if (errorCode == KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED
                        || errorCode == KrbErrorCode.KRB_AP_ERR_TKT_NYV
                        || errorCode == KrbErrorCode.KDC_ERR_TGT_REVOKED
                        || errorCode == KrbErrorCode.KRB_AP_ERR_NO_TGT) {
                    return true;
                }
            }
            return false;
        }

        private static @Nullable KrbErrorCode krbErrorCode(Throwable failure) {
            if (failure instanceof KrbErrorException) {
                return ((KrbErrorException) failure).getKrbError() == null
                        ? null : ((KrbErrorException) failure).getKrbError().getErrorCode();
            }
            return failure instanceof KrbException ? ((KrbException) failure).getKrbErrorCode() : null;
        }
    }

    static class KerbyCredentials {
        private final Callable<TgtTicket> tgtRequester;
        private final Clock clock;
        private final Duration tgtRefreshMargin;
        private final Lock lock = new ReentrantLock();
        private TgtCacheState tgtState = TgtCacheState.empty();
        // Guarded by lock and tied by identity to the cache generation that failed.
        private @Nullable TgtRefreshFailure refreshFailure;

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

        private Subject getServiceSubject(TgtTicket tgt, String servicePrincipal) throws Exception {
            KrbClient client = createClient();
            SgtTicket sgt = client.requestSgt(tgt, servicePrincipal);
            PrincipalName clientPrincipal = sgt.getClientPrincipal() == null ? tgt.getClientPrincipal() : sgt.getClientPrincipal();
            return subjectWithTickets(clientPrincipal, tgt, sgt);
        }

        TgtTicket getTgtTicket() throws Exception {
            Instant refreshRequestedAt = clock.instant();
            lock.lock();
            try {
                TgtCacheState state = tgtState;
                if (state.requiresRefresh(clock, tgtRefreshMargin)) {
                    throwCachedRefreshFailure(state, refreshRequestedAt);
                    state = refreshTgt(state);
                }
                return Objects.requireNonNull(state.tgt);
            } finally {
                lock.unlock();
            }
        }

        private TgtCacheState refreshTgt(TgtCacheState refreshTarget) throws Exception {
            try {
                TgtTicket refreshedTgt = tgtRequester.call();
                // Validate against completion time so a TGT that expired during acquisition is never published.
                Instant refreshedAt = clock.instant();
                Instant endTime = requireCurrentTgtEndTime(refreshedTgt, refreshedAt);
                // Retry halfway through the remaining lifetime, with bounds that avoid request-rate polling.
                Instant retryAt = refreshTarget.tgt != null
                        && !endTime.isAfter(refreshedAt.plus(tgtRefreshMargin))
                        ? nextProactiveRefreshAt(refreshedAt, endTime) : refreshedAt;
                TgtCacheState refreshedState = TgtCacheState.withTgt(refreshedTgt, retryAt);
                tgtState = refreshedState;
                refreshFailure = null;
                return refreshedState;
            } catch (InterruptedException e) {
                // Interruption is caller-specific and must not become a shared authentication failure.
                Thread.currentThread().interrupt();
                throw e;
            } catch (RuntimeException e) {
                return handleRefreshFailure(refreshTarget, e);
            } catch (Exception e) {
                return handleRefreshFailure(refreshTarget, e);
            }
        }

        private TgtCacheState handleRefreshFailure(TgtCacheState refreshTarget, Exception failure) throws Exception {
            Instant failedAt = clock.instant();
            TgtCacheState retainedState = refreshTarget.afterFailedProactiveRefresh(failedAt);
            if (tgtState == refreshTarget && retainedState != null) {
                // Keep a still-current TGT, but publish its later retry deadline in the same state transition.
                tgtState = retainedState;
                refreshFailure = null;
                return retainedState;
            }

            publishRefreshFailure(refreshTarget, failure);
            throw failure;
        }

        private void throwCachedRefreshFailure(TgtCacheState refreshTarget, Instant refreshRequestedAt)
                throws Exception {
            if (refreshFailure == null) {
                return;
            }
            if (refreshFailure.refreshTarget == refreshTarget
                    && (refreshRequestedAt.isBefore(refreshFailure.retryAt)
                        || clock.instant().isBefore(refreshFailure.retryAt))) {
                throw refreshFailure.failure;
            }
            refreshFailure = null;
        }

        private void publishRefreshFailure(TgtCacheState refreshTarget, Exception failure) {
            refreshFailure = new TgtRefreshFailure(refreshTarget, failure,
                    clock.instant().plus(REFRESH_FAILURE_COOLDOWN));
        }

        void invalidateTgtTicket(TgtTicket failedTgt) {
            lock.lock();
            try {
                // Identity comparison prevents a late failure from evicting a newer TGT.
                if (tgtState.tgt == failedTgt) {
                    tgtState = TgtCacheState.empty();
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

        private static boolean isCurrent(@Nullable TgtTicket tgtTicket, Instant instant) {
            Instant endTime = tgtEndTime(tgtTicket);
            return endTime != null && endTime.isAfter(instant);
        }

        private static @Nullable Instant tgtEndTime(@Nullable TgtTicket tgtTicket) {
            try {
                EncKdcRepPart encKdcRepPart = tgtTicket == null ? null : tgtTicket.getEncKdcRepPart();
                KerberosTime endTime = encKdcRepPart == null ? null : encKdcRepPart.getEndTime();
                return endTime == null ? null : Instant.ofEpochMilli(endTime.getTime());
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        private static boolean isInsideMargin(TgtTicket tgtTicket, Instant now, Duration refreshMargin) {
            return !isCurrent(tgtTicket, now.plus(refreshMargin));
        }

        private static Instant requireCurrentTgtEndTime(@Nullable TgtTicket tgtTicket, Instant instant) {
            if (tgtTicket == null) {
                throw new IllegalStateException("Kerby TGT requester returned null");
            }
            EncKdcRepPart encKdcRepPart = tgtTicket.getEncKdcRepPart();
            KerberosTime endTime = encKdcRepPart == null ? null : encKdcRepPart.getEndTime();
            if (endTime == null) {
                throw new IllegalStateException("Kerby TGT requester returned a malformed TGT without an end time");
            }
            Instant end = Instant.ofEpochMilli(endTime.getTime());
            if (!end.isAfter(instant)) {
                throw new IllegalStateException("Kerby TGT requester returned an expired TGT");
            }
            return end;
        }

        private static Instant nextProactiveRefreshAt(Instant now, Instant endTime) {
            Duration delay = Duration.between(now, endTime).dividedBy(2);
            if (delay.compareTo(MIN_PROACTIVE_RETRY_DELAY) < 0) {
                delay = MIN_PROACTIVE_RETRY_DELAY;
            } else if (delay.compareTo(MAX_PROACTIVE_RETRY_DELAY) > 0) {
                delay = MAX_PROACTIVE_RETRY_DELAY;
            }
            return now.plus(delay);
        }

        private static class TgtCacheState {

            private final @Nullable TgtTicket tgt;
            private final Instant proactiveRetryAt;

            private TgtCacheState(@Nullable TgtTicket tgt, Instant proactiveRetryAt) {
                this.tgt = tgt;
                this.proactiveRetryAt = proactiveRetryAt;
            }

            private static TgtCacheState empty() {
                return new TgtCacheState(null, Instant.MIN);
            }

            private static TgtCacheState withTgt(TgtTicket tgt, Instant proactiveRetryAt) {
                return new TgtCacheState(tgt, proactiveRetryAt);
            }

            private boolean requiresRefresh(Clock clock, Duration refreshMargin) {
                Instant now = clock.instant();
                if (!isCurrent(tgt, now)) {
                    return true;
                }
                return isInsideMargin(tgt, now, refreshMargin) && !now.isBefore(proactiveRetryAt);
            }

            private @Nullable TgtCacheState afterFailedProactiveRefresh(Instant failedAt) {
                Instant endTime = tgtEndTime(tgt);
                if (tgt == null || endTime == null || !endTime.isAfter(failedAt)) {
                    return null;
                }
                return withTgt(tgt, nextProactiveRefreshAt(failedAt, endTime));
            }
        }

        private static class TgtRefreshFailure {

            private final TgtCacheState refreshTarget;
            private final Exception failure;
            private final Instant retryAt;

            private TgtRefreshFailure(TgtCacheState refreshTarget, Exception failure, Instant retryAt) {
                this.refreshTarget = refreshTarget;
                this.failure = failure;
                this.retryAt = retryAt;
            }
        }

    }

    // Records the exact TGT used by one TGT/TGS/GSS attempt for identity-safe invalidation.
    private static class ContextAttempt {

        private @Nullable TgtTicket tgt;
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
