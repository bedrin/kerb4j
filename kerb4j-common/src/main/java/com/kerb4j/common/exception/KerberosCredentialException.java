package com.kerb4j.common.exception;

public class KerberosCredentialException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosCredentialException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
