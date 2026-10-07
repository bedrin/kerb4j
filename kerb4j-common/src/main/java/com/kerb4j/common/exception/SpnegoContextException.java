package com.kerb4j.common.exception;

public class SpnegoContextException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public SpnegoContextException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
