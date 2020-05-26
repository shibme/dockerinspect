package me.shib.security.trivy;

enum TrivyStewardEnv {

    TRIVY_TARGET_IMAGE,
    TRIVY_STEWARD_PROJECT,
    TRIVY_STEWARD_SKIP_SCAN;

    private String getValue() {
        String val = System.getenv(name());
        if (val != null && val.isEmpty()) {
            return null;
        }
        return val;
    }

    String getAsString() {
        return getValue();
    }

    boolean getAsBoolean() {
        try {
            return getValue().equalsIgnoreCase("TRUE");
        } catch (Exception e) {
            return false;
        }
    }

}
