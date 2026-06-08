package com.kerb4j.common.exception;

/**
 * Base runtime exception for Kerb4J failures that have been translated into actionable diagnostics.
 * <p>
 * The original JGSS, JAAS, Kerby, or parsing exception is preserved as the cause. Use {@link #getDiagnostic()} for
 * stable error classification instead of parsing provider-specific exception messages.
 */
public class Kerb4JKerberosException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final KerberosDiagnostic diagnostic;

    public Kerb4JKerberosException(KerberosDiagnostic diagnostic, Throwable cause) {
        super(diagnostic.toSupportString(), cause);
        this.diagnostic = diagnostic;
    }

    public KerberosDiagnostic getDiagnostic() {
        return diagnostic;
    }

    public KerberosFailureCode getFailureCode() {
        return diagnostic.getCode();
    }

    public KerberosFailureCategory getFailureCategory() {
        return diagnostic.getCategory();
    }
}
