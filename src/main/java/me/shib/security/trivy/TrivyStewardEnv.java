package me.shib.security.trivy;

enum TrivyStewardEnv {

    TS_TARGET_IMAGE(true),
    TS_PROJECT_NAME(true),
    TS_DEPENDENCY_SCAN(false);

    private final boolean required;

    TrivyStewardEnv(boolean required) {
        this.required = required;
    }

    static void validateEnv() throws TrivyException {
        for (TrivyStewardEnv env : TrivyStewardEnv.values()) {
            if (env.required && env.getValue() == null) {
                throw new TrivyException("Please set " + env.name());
            }
        }
    }

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
