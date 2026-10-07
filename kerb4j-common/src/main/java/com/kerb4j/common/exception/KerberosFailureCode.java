package com.kerb4j.common.exception;

/**
 * Stable, machine-readable Kerberos failure identifiers.
 * <p>
 * Keep these names explicit rather than clever: they are intended for logs, support tickets, and AI-assisted
 * troubleshooting where the exact Java exception class is often less useful than the failure mode.
 */
public enum KerberosFailureCode {
    UNKNOWN,
    KRB5_CONFIG_NOT_FOUND,
    REALM_NOT_CONFIGURED,
    KDC_NOT_FOUND,
    KDC_UNREACHABLE,
    CLOCK_SKEW_TOO_LARGE,
    CLIENT_PRINCIPAL_NOT_FOUND,
    SERVER_PRINCIPAL_NOT_FOUND,
    BAD_CREDENTIALS,
    PREAUTHENTICATION_FAILED,
    CREDENTIALS_EXPIRED,
    TICKET_CACHE_NOT_FOUND,
    TGT_NOT_FOUND,
    KEYTAB_NOT_FOUND,
    KEYTAB_MISSING_PRINCIPAL,
    KEY_VERSION_MISMATCH,
    UNSUPPORTED_ENCRYPTION_TYPE,
    CANNOT_DECRYPT_TICKET,
    TOKEN_EMPTY,
    TOKEN_MALFORMED,
    TOKEN_NOT_SPNEGO,
    UNSUPPORTED_MECHANISM,
    REPLAY_DETECTED,
    MUTUAL_AUTHENTICATION_FAILED,
    PROVIDER_NOT_AVAILABLE,
    UNSUPPORTED_OPERATION
}
