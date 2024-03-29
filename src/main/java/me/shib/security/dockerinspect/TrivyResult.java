package me.shib.security.dockerinspect;

import com.google.gson.annotations.SerializedName;

import java.util.List;

final class TrivyResult {

    @SerializedName("Target")
    private String target;
    @SerializedName("Class")
    private String resultClass;
    @SerializedName("Type")
    private String type;
    @SerializedName("Vulnerabilities")
    private List<Vulnerability> vulnerabilities;

    String getTarget() {
        return target;
    }

    String getResultClass() {
        return resultClass;
    }

    String getType() {
        return type;
    }

    List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}
