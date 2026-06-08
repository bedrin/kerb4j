package com.kerb4j.common.exception;

public class KerberosCommunicationException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosCommunicationException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
