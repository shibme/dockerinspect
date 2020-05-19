package me.shib.security.trivy;

import com.google.gson.annotations.SerializedName;

import java.util.List;

final class TrivyReport {

    @SerializedName("Target")
    private String target;
    @SerializedName("Type")
    private String type;
    @SerializedName("Vulnerabilities")
    private List<Vulnerability> vulnerabilities;

    String getTarget() {
        return target;
    }

    String getType() {
        return type;
    }

    List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}
