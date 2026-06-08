package com.kerb4j.common.exception;

public class KerberosServicePrincipalException extends Kerb4JKerberosException {
    private static final long serialVersionUID = 1L;

    public KerberosServicePrincipalException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic, cause);
    }
}
