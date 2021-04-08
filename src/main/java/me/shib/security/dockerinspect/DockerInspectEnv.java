package me.shib.security.dockerinspect;

enum DockerInspectEnv {

    DOCKERINSPECT_TARGET_IMAGE("The image name with tag [Better if available locally. If not, it will be pulled]", true),
    DOCKERINSPECT_PROJECT_NAME("A unique project name for the scan to avoid duplicate issues", true),
    DOCKERINSPECT_DEPENDENCY_SCAN("Set TRUE if application dependency vulnerabilities also need to be considered", false),
    DOCKERINSPECT_IGNORE_UNFIXED("Set TRUE to ignore unfixed vulnerabilities", false),
    DOCKERINSPECT_CLEAR_CACHE("Set TRUE to clear trivy cache directory", false);

    private final String definition;
    private final boolean required;

    DockerInspectEnv(String definition, boolean required) {
        this.definition = definition;
        this.required = required;
    }

    static String getVarDefinitions() {
        StringBuilder varDefinitions = new StringBuilder();
        for (DockerInspectEnv env : DockerInspectEnv.values()) {
            varDefinitions.append("\n").append(env).append("\n")
                    .append("\t- ").append(env.definition);
        }
        return varDefinitions.toString();
    }

    static void validateEnv() throws DockerInspectException {
        for (DockerInspectEnv env : DockerInspectEnv.values()) {
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
