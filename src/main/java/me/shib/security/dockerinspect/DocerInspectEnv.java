package me.shib.security.dockerinspect;

enum DocerInspectEnv {

    DOCKERINSPECT_TARGET_IMAGE("The image name with tag [Better if available locally. If not, it will be pulled]", true),
    DOCKERINSPECT_PROJECT_NAME("A unique project name for the scan to avoid duplicate issues", true),
    DOCKERINSPECT_DEPENDENCY_SCAN("Set TRUE if application dependency vulnerabilities also need to be considered", false);

    private final String definition;
    private final boolean required;

    DocerInspectEnv(String definition, boolean required) {
        this.definition = definition;
        this.required = required;
    }

    static String getVarDefinitions() {
        StringBuilder varDefinitions = new StringBuilder();
        for (DocerInspectEnv env : DocerInspectEnv.values()) {
            varDefinitions.append("\n").append(env).append("\n")
                    .append("\t- ").append(env.definition);
        }
        return varDefinitions.toString();
    }

    static void validateEnv() throws DockerInspectException {
        for (DocerInspectEnv env : DocerInspectEnv.values()) {
            if (env.required && env.getValue() == null) {
                throw new DockerInspectException("Please set " + env.name());
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
