package com.kerb4j.common.exception;

public class KerberosClockSkewException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosClockSkewException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
