package com.kerb4j.common.exception;

public class KerberosProviderException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosProviderException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
