package com.kerb4j.common.exception;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Human-readable and machine-readable explanation of a Kerberos failure.
 */
public final class KerberosDiagnostic {

    private final KerberosFailureCode code;
    private final KerberosFailureCategory category;
    private final String operation;
    private final String summary;
    private final List<String> likelyCauses;
    private final List<String> suggestedActions;
    private final String originalExceptionType;
    private final String originalMessage;

    private KerberosDiagnostic(Builder builder) {
        this.code = Objects.requireNonNull(builder.code, "code must not be null");
        this.category = Objects.requireNonNull(builder.category, "category must not be null");
        this.operation = builder.operation;
        this.summary = Objects.requireNonNull(builder.summary, "summary must not be null");
        this.likelyCauses = Collections.unmodifiableList(new ArrayList<>(builder.likelyCauses));
        this.suggestedActions = Collections.unmodifiableList(new ArrayList<>(builder.suggestedActions));
        this.originalExceptionType = builder.originalExceptionType;
        this.originalMessage = builder.originalMessage;
    }

    public KerberosFailureCode getCode() {
        return code;
    }

    public KerberosFailureCategory getCategory() {
        return category;
    }

    public String getOperation() {
        return operation;
    }

    public String getSummary() {
        return summary;
    }

    public List<String> getLikelyCauses() {
        return likelyCauses;
    }

    public List<String> getSuggestedActions() {
        return suggestedActions;
    }

    public String getOriginalExceptionType() {
        return originalExceptionType;
    }

    public String getOriginalMessage() {
        return originalMessage;
    }

    public String toSupportString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Kerberos failure [").append(code).append("]");
        if (operation != null && !operation.isEmpty()) {
            builder.append(" during ").append(operation);
        }
        builder.append(": ").append(summary);
        appendList(builder, " Likely cause(s): ", likelyCauses);
        appendList(builder, " Suggested action(s): ", suggestedActions);
        if (originalExceptionType != null && !originalExceptionType.isEmpty()) {
            builder.append(" Original exception: ").append(originalExceptionType);
            if (originalMessage != null && !originalMessage.isEmpty()) {
                builder.append(": ").append(originalMessage);
            }
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        return toSupportString();
    }

    public static Builder builder(KerberosFailureCode code, KerberosFailureCategory category, String summary) {
        return new Builder(code, category, summary);
    }

    private static void appendList(StringBuilder builder, String label, List<String> values) {
        if (values.isEmpty()) {
            return;
        }
        builder.append(label);
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                builder.append("; ");
            }
            builder.append(values.get(i));
        }
        builder.append('.');
    }

    public static final class Builder {
        private final KerberosFailureCode code;
        private final KerberosFailureCategory category;
        private final String summary;
        private final List<String> likelyCauses = new ArrayList<>();
        private final List<String> suggestedActions = new ArrayList<>();
        private String operation;
        private String originalExceptionType;
        private String originalMessage;

        private Builder(KerberosFailureCode code, KerberosFailureCategory category, String summary) {
            this.code = code;
            this.category = category;
            this.summary = summary;
        }

        public Builder operation(String operation) {
            this.operation = operation;
            return this;
        }

        public Builder likelyCause(String likelyCause) {
            if (likelyCause != null && !likelyCause.isEmpty()) {
                this.likelyCauses.add(likelyCause);
            }
            return this;
        }

        public Builder suggestedAction(String suggestedAction) {
            if (suggestedAction != null && !suggestedAction.isEmpty()) {
                this.suggestedActions.add(suggestedAction);
            }
            return this;
        }

        public Builder original(Throwable throwable) {
            if (throwable != null) {
                this.originalExceptionType = throwable.getClass().getName();
                this.originalMessage = throwable.getMessage();
            }
            return this;
        }

        public KerberosDiagnostic build() {
            return new KerberosDiagnostic(this);
        }
    }
}
