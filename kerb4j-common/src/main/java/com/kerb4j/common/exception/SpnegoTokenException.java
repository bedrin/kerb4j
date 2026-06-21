package com.kerb4j.common.exception;

public class SpnegoTokenException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public SpnegoTokenException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
