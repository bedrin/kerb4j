package com.kerb4j.common.exception;

public class KerberosEncryptionException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosEncryptionException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
