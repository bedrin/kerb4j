package com.kerb4j.common.exception;

import org.ietf.jgss.GSSException;

import javax.security.auth.login.LoginException;
import java.io.FileNotFoundException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Converts provider-specific Kerberos/JGSS/JAAS exceptions into stable Kerb4J diagnostics.
 */
public final class KerberosFailureAnalyzer {

    private KerberosFailureAnalyzer() {
    }

    public static Kerb4JKerberosException wrap(String operation, Throwable throwable) {
        if (throwable instanceof Kerb4JKerberosException) {
            return (Kerb4JKerberosException) throwable;
        }
        Throwable original = unwrapPrivilegedAction(throwable);
        KerberosDiagnostic diagnostic = diagnose(operation, original == null ? throwable : original);
        return exceptionFor(diagnostic, throwable);
    }

    public static Kerb4JKerberosException explicit(String operation,
                                                   KerberosFailureCode code,
                                                   KerberosFailureCategory category,
                                                   String summary,
                                                   Throwable throwable,
                                                   String likelyCause,
                                                   String suggestedAction) {
        KerberosDiagnostic diagnostic = KerberosDiagnostic.builder(code, category, summary)
                .operation(operation)
                .likelyCause(likelyCause)
                .suggestedAction(suggestedAction)
                .original(throwable)
                .build();
        return exceptionFor(diagnostic, throwable);
    }

    public static KerberosDiagnostic diagnose(String operation, Throwable throwable) {
        Throwable root = mostSpecificCause(throwable);
        String text = searchableText(throwable);
        KerberosDiagnostic.Builder builder = builderFor(operation, root, text);
        return builder.original(root == null ? throwable : root).build();
    }

    private static KerberosDiagnostic.Builder builderFor(String operation, Throwable throwable, String text) {
        KerberosDiagnostic.Builder builder;

        if (contains(text, "clock skew", "skew too great", "krb_ap_err_skew")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.CLOCK_SKEW_TOO_LARGE,
                            KerberosFailureCategory.CLOCK,
                            "The client, server, or KDC clocks differ too much for Kerberos to trust the ticket.")
                    .likelyCause("Kerberos normally accepts only a small time difference, often five minutes")
                    .suggestedAction("Synchronize the client, application server, and domain controller/KDC clocks with NTP");
        } else if (contains(text, "cannot locate default realm", "default realm", "realm not specified", "realm is null")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.REALM_NOT_CONFIGURED,
                            KerberosFailureCategory.CONFIGURATION,
                            "Kerberos cannot determine which realm to use.")
                    .likelyCause("java.security.krb5.conf is missing default_realm or the principal is not realm-qualified")
                    .suggestedAction("Set java.security.krb5.conf to a readable krb5.conf with default_realm, or use a principal like user@REALM");
        } else if (contains(text, "krb5.conf", "krb5 config") && contains(text, "cannot read", "not found", "no such file")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KRB5_CONFIG_NOT_FOUND,
                            KerberosFailureCategory.CONFIGURATION,
                            "Kerberos configuration cannot be read.")
                    .likelyCause("The java.security.krb5.conf path is wrong or not readable by the JVM")
                    .suggestedAction("Check the java.security.krb5.conf system property and file permissions");
        } else if (contains(text, "cannot find kdc", "unable to locate kdc", "kdc has no support", "kdc configuration", "dns lookup kdc")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KDC_NOT_FOUND,
                            KerberosFailureCategory.NETWORK,
                            "Kerberos cannot find a KDC for the realm.")
                    .likelyCause("krb5.conf has no kdc entry for the realm and DNS KDC lookup is unavailable or disabled")
                    .suggestedAction("Add [realms] realm kdc entries to krb5.conf or enable DNS KDC lookup");
        } else if (isNetworkException(throwable) || contains(text, "connection refused", "timeout", "timed out", "no route to host", "unknown host", "network is unreachable")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KDC_UNREACHABLE,
                            KerberosFailureCategory.NETWORK,
                            "Kerb4J found a KDC name, but the JVM could not reach it.")
                    .likelyCause("Firewall, DNS, routing, or KDC service availability problem")
                    .suggestedAction("Verify DNS resolution and TCP/UDP connectivity from the application host to the KDC");
        } else if (contains(text, "client not found", "client not found in kerberos database", "principal unknown", "client principal unknown")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.CLIENT_PRINCIPAL_NOT_FOUND,
                            KerberosFailureCategory.CREDENTIALS,
                            "The user/client principal does not exist in the Kerberos database.")
                    .likelyCause("The username or realm is wrong, or the account has not been created in the KDC/Active Directory")
                    .suggestedAction("Verify the exact principal name and realm, including case and @REALM suffix");
        } else if (contains(text, "server not found", "server not found in kerberos database", "server principal unknown", "sname")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.SERVER_PRINCIPAL_NOT_FOUND,
                            KerberosFailureCategory.SERVICE_PRINCIPAL,
                            "The requested service principal name (SPN) is not registered in Kerberos.")
                    .likelyCause("The SPN in the request does not match any service account, or DNS/canonical hostname changed the SPN")
                    .suggestedAction("Register the SPN, for example HTTP/host.example.com@REALM, and make the client URL host match it");
        } else if (contains(text, "pre-authentication", "preauthentication", "preauth", "integrity check on decrypted field failed")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.PREAUTHENTICATION_FAILED,
                            KerberosFailureCategory.CREDENTIALS,
                            "Kerberos pre-authentication failed before a ticket was issued.")
                    .likelyCause("Wrong password, wrong keytab key, disabled account, or unsupported pre-authentication policy")
                    .suggestedAction("Check the password/keytab for the principal and inspect KDC/Active Directory logs for the account");
        } else if (contains(text, "password incorrect", "bad password", "invalid password", "credentials are invalid", "login failure")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.BAD_CREDENTIALS,
                            KerberosFailureCategory.CREDENTIALS,
                            "The supplied Kerberos credentials were rejected.")
                    .likelyCause("Wrong password or principal")
                    .suggestedAction("Retry with the exact Kerberos principal and password; for AD, check lockout/disabled state");
        } else if (contains(text, "ticket expired", "credentials expired", "expired kerberos", "failed to renew")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.CREDENTIALS_EXPIRED,
                            KerberosFailureCategory.CREDENTIALS,
                            "The Kerberos ticket or credential has expired.")
                    .likelyCause("The TGT/service ticket lifetime ended, or renewal failed")
                    .suggestedAction("Acquire a new ticket, refresh the login context, or reduce credential caching lifetime assumptions");
        } else if (contains(text, "ticket cache", "credential cache", "krb5ccname", "ccache")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.TICKET_CACHE_NOT_FOUND,
                            KerberosFailureCategory.CREDENTIALS,
                            "Kerberos ticket-cache login could not find a usable credential cache.")
                    .likelyCause("KRB5CCNAME is unset, points to an unsupported cache type, or the process cannot read the cache")
                    .suggestedAction("Run kinit for the principal or set KRB5CCNAME to a readable FILE cache");
        } else if (contains(text, "no tgt", "failed to find any kerberos tgt", "tgt not found", "krbtgt")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.TGT_NOT_FOUND,
                            KerberosFailureCategory.CREDENTIALS,
                            "No Ticket Granting Ticket (TGT) is available for initiating Kerberos authentication.")
                    .likelyCause("The subject was created for accept-only use, the ticket cache is empty, or login did not issue a TGT")
                    .suggestedAction("Use initiator credentials for outbound calls; accept-only keytabs can only validate incoming tickets");
        } else if (contains(text, "keytab") && contains(text, "not found", "no such file", "cannot read", "does not exist")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KEYTAB_NOT_FOUND,
                            KerberosFailureCategory.CONFIGURATION,
                            "The configured keytab file cannot be read.")
                    .likelyCause("The keytab path is wrong, points to a classpath resource JAAS cannot read, or lacks file permissions")
                    .suggestedAction("Use an absolute file-system keytab path and verify permissions for the JVM user");
        } else if (contains(text, "keytab", "key table") && contains(text, "principal", "not found", "no key")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KEYTAB_MISSING_PRINCIPAL,
                            KerberosFailureCategory.CREDENTIALS,
                            "The keytab does not contain a key for the configured service principal.")
                    .likelyCause("The servicePrincipal setting and keytab entries do not match")
                    .suggestedAction("List the keytab with klist -kte and compare it to the configured service principal");
        } else if (contains(text, "kvno", "key version", "specified version of key is not available")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.KEY_VERSION_MISMATCH,
                            KerberosFailureCategory.ENCRYPTION,
                            "The ticket was encrypted with a different key version than the keytab contains.")
                    .likelyCause("The service account password changed after the keytab was generated")
                    .suggestedAction("Regenerate and redeploy the keytab for the current service account key version");
        } else if (contains(text, "encryption type", "etype", "enctype", "unsupported key type", "cannot find key of appropriate type")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.UNSUPPORTED_ENCRYPTION_TYPE,
                            KerberosFailureCategory.ENCRYPTION,
                            "The ticket uses an encryption type that the JVM, KDC, or keytab cannot use.")
                    .likelyCause("The KDC issued an enctype not present in the keytab or disabled in the JVM/KDC policy")
                    .suggestedAction("Regenerate the keytab with supported enctypes and check permitted_enctypes/default_tkt_enctypes settings");
        } else if (contains(text, "checksum failed", "message stream modified", "cannot decrypt", "decryption failed", "integrity check failed")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.CANNOT_DECRYPT_TICKET,
                            KerberosFailureCategory.ENCRYPTION,
                            "Kerb4J could not decrypt or verify the Kerberos ticket.")
                    .likelyCause("Wrong service principal, wrong keytab, wrong key version, or ticket encrypted for another service")
                    .suggestedAction("Verify the incoming token target SPN and compare it with keytab entries and key versions");
        } else if (contains(text, "request is a replay", "krb_ap_err_repeat", "replay")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.REPLAY_DETECTED,
                            KerberosFailureCategory.SPNEGO_TOKEN,
                            "The KDC/JGSS layer detected a replayed Kerberos authenticator.")
                    .likelyCause("The same SPNEGO token was reused, retried through a proxy, or replay-cache state collided")
                    .suggestedAction("Create a fresh token per request and inspect proxy/retry behavior");
        } else if (contains(text, "defective token", "gssheader", "asn.1", "asn1", "malformed", "invalid token")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.TOKEN_MALFORMED,
                            KerberosFailureCategory.SPNEGO_TOKEN,
                            "The received Negotiate token is malformed or not parseable as SPNEGO/Kerberos.")
                    .likelyCause("The Authorization header is truncated, not Base64-decoded correctly, or is not a Kerberos/SPNEGO token")
                    .suggestedAction("Pass the raw bytes from the Base64 part of the 'Authorization: Negotiate ...' header without modification");
        } else if (contains(text, "spnego", "negotiate") && contains(text, "mechanism", "oid", "unsupported")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.UNSUPPORTED_MECHANISM,
                            KerberosFailureCategory.SPNEGO_TOKEN,
                            "The token does not contain a Kerberos mechanism supported by Kerb4J.")
                    .likelyCause("The peer selected NTLM or another mechanism instead of Kerberos")
                    .suggestedAction("Ensure the browser/client and server are configured for Kerberos Negotiate, not NTLM fallback");
        } else if (throwable instanceof LoginException || contains(text, "loginexception")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.BAD_CREDENTIALS,
                            KerberosFailureCategory.CREDENTIALS,
                            "JAAS Kerberos login failed.")
                    .likelyCause("Kerberos rejected the configured principal, password, keytab, or ticket cache")
                    .suggestedAction("Enable sun.security.krb5.debug=true and check principal, realm, keytab, and krb5.conf");
        } else if (throwable instanceof GSSException || contains(text, "gssexception")) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.MUTUAL_AUTHENTICATION_FAILED,
                            KerberosFailureCategory.GSS_CONTEXT,
                            "JGSS could not create or advance the SPNEGO security context.")
                    .likelyCause("The lower-level Kerberos exchange failed; inspect the original GSS major/minor strings")
                    .suggestedAction("Check the original exception in this cause chain and enable Kerberos debug logging if needed");
        } else if (throwable instanceof UnsupportedOperationException) {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.UNSUPPORTED_OPERATION,
                            KerberosFailureCategory.PROVIDER,
                            "The selected Kerb4J provider does not support this Kerberos operation.")
                    .likelyCause("The operation requires a different SPNEGO provider")
                    .suggestedAction("Select another provider with -Dkerb4j.spnego.provider or add the required module to the classpath");
        } else {
            builder = KerberosDiagnostic.builder(KerberosFailureCode.UNKNOWN,
                            KerberosFailureCategory.UNKNOWN,
                            "Kerb4J could not classify this Kerberos failure automatically.")
                    .likelyCause("The provider returned an uncommon or vendor-specific exception")
                    .suggestedAction("Use the original exception message and enable Kerberos debug logging for deeper analysis");
        }

        return builder.operation(operation);
    }

    private static Kerb4JKerberosException exceptionFor(KerberosDiagnostic diagnostic, Throwable cause) {
        switch (diagnostic.getCategory()) {
            case CONFIGURATION:
                return new KerberosConfigurationException(diagnostic, cause);
            case CREDENTIALS:
                return new KerberosCredentialException(diagnostic, cause);
            case SERVICE_PRINCIPAL:
                return new KerberosServicePrincipalException(diagnostic, cause);
            case NETWORK:
                return new KerberosCommunicationException(diagnostic, cause);
            case CLOCK:
                return new KerberosClockSkewException(diagnostic, cause);
            case ENCRYPTION:
                return new KerberosEncryptionException(diagnostic, cause);
            case SPNEGO_TOKEN:
                return new SpnegoTokenException(diagnostic, cause);
            case PROVIDER:
                return new KerberosProviderException(diagnostic, cause);
            case GSS_CONTEXT:
            case UNKNOWN:
            default:
                return new SpnegoContextException(diagnostic, cause);
        }
    }

    private static Throwable unwrapPrivilegedAction(Throwable throwable) {
        if (throwable instanceof PrivilegedActionException) {
            return ((PrivilegedActionException) throwable).getException();
        }
        return throwable;
    }

    private static Throwable mostSpecificCause(Throwable throwable) {
        Throwable current = unwrapPrivilegedAction(throwable);
        List<Throwable> seen = new ArrayList<>();
        while (current != null && current.getCause() != null && !seen.contains(current.getCause())) {
            seen.add(current);
            current = unwrapPrivilegedAction(current.getCause());
        }
        return current;
    }

    private static String searchableText(Throwable throwable) {
        StringBuilder builder = new StringBuilder();
        Throwable current = throwable;
        List<Throwable> seen = new ArrayList<>();
        while (current != null && !seen.contains(current)) {
            seen.add(current);
            builder.append(' ').append(current.getClass().getName());
            if (current.getMessage() != null) {
                builder.append(' ').append(current.getMessage());
            }
            if (current instanceof GSSException) {
                GSSException gssException = (GSSException) current;
                builder.append(' ').append(gssException.getMajorString());
                builder.append(' ').append(gssException.getMinorString());
            }
            current = current.getCause();
        }
        return builder.toString().toLowerCase(Locale.ROOT);
    }

    private static boolean contains(String text, String... tokens) {
        for (String token : tokens) {
            if (text.contains(token.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNetworkException(Throwable throwable) {
        Throwable current = throwable;
        List<Throwable> seen = new ArrayList<>();
        while (current != null && !seen.contains(current)) {
            seen.add(current);
            if (current instanceof UnknownHostException
                    || current instanceof ConnectException
                    || current instanceof SocketTimeoutException
                    || current instanceof NoRouteToHostException
                    || current instanceof FileNotFoundException) {
                return !(current instanceof FileNotFoundException);
            }
            current = current.getCause();
        }
        return false;
    }
}
