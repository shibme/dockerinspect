package me.shib.security.dockerinspect;

public final class DockerInspectException extends Exception {
    DockerInspectException(String message) {
        super(message);
    }

    DockerInspectException(Exception e) {
        super(e.getMessage());
    }
}