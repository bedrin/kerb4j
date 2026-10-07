package com.kerb4j.common.exception;

public enum KerberosFailureCategory {
    CONFIGURATION,
    CREDENTIALS,
    SERVICE_PRINCIPAL,
    NETWORK,
    CLOCK,
    ENCRYPTION,
    SPNEGO_TOKEN,
    GSS_CONTEXT,
    PROVIDER,
    UNKNOWN
}
