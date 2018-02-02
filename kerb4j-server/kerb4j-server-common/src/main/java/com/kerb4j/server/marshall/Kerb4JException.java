package com.kerb4j.server.marshall;

import java.text.MessageFormat;
import java.util.ResourceBundle;

public class Kerb4JException extends Exception {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle MESSAGES = ResourceBundle
            .getBundle("exceptions");

    private final Throwable cause;

    public Kerb4JException() {
        this(null, null);
    }

    public Kerb4JException(String message) {
        this(message, null);
    }

    public Kerb4JException(Throwable cause) {
        this(null, cause);
    }

    public Kerb4JException(String key, Object[] args, Throwable cause) {
        this(MessageFormat.format(MESSAGES.getString(key), args), cause);
    }

    public Kerb4JException(String message, Throwable cause) {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause() {
        return cause;
    }

}
