package me.shib.security.trivy;

public final class TrivyException extends Exception {
    TrivyException(String message) {
        super(message);
    }

    TrivyException(Exception e) {
        super(e.getMessage());
    }
}