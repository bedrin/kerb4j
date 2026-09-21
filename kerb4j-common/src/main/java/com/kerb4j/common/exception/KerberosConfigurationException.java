package com.kerb4j.common.exception;

public class KerberosConfigurationException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosConfigurationException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
