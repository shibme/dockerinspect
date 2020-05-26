package me.shib.security.trivy;

import me.shib.steward.StewardData;
import me.shib.steward.StewardFinding;

import java.util.List;

class TSConvert {

    private static final transient String cveBaseURL = "https://nvd.nist.gov/vuln/detail/";
    private static final transient String toolName = "Trivy";

    private static String getUrlForCVE(String cve) throws TrivyException {
        if (cve != null && cve.toUpperCase().startsWith("CVE")) {
            return cveBaseURL + cve;
        }
        throw new TrivyException("CVE provided is not valid");
    }

    static StewardData toStewardData(List<TrivyReport> reports) throws TrivyException {
        String projectName = TrivyStewardEnv.TRIVY_STEWARD_PROJECT.getAsString();
        if (projectName == null || projectName.isEmpty()) {
            throw new TrivyException("Set " + TrivyStewardEnv.TRIVY_STEWARD_PROJECT);
        }
        StewardData data = new StewardData(projectName, toolName);
        data.addContext(projectName);
        for (TrivyReport report : reports) {
            if (report.getVulnerabilities() != null) {
                for (Vulnerability vulnerability : report.getVulnerabilities()) {
                    String title = "Vulnerability [" + vulnerability.getVulnerabilityId() + "] found in " +
                            vulnerability.getPackageName() + " of " + report.getTarget();
                    StewardFinding finding = new StewardFinding(title,
                            vulnerability.getSeverity().getPriority());
                    finding.addContext(report.getType());
                    StringBuilder description = new StringBuilder();
                    description.append("A vulnerable component (**").append(vulnerability.getPackageName())
                            .append("-").append(vulnerability.getInstalledVersion()).append("**) was found in ")
                            .append("**").append(report.getTarget()).append(" [").append(report.getType())
                            .append("]**.\n\n");
                    try {
                        description.append("**[").append(vulnerability.getVulnerabilityId()).append("](")
                                .append(getUrlForCVE(vulnerability.getVulnerabilityId())).append("):**");
                    } catch (TrivyException e) {
                        description.append("**").append(vulnerability.getVulnerabilityId()).append(":**");
                    }
                    description.append("\n");
                    description.append(" * **Package Name:** ").append(vulnerability.getPackageName()).append("\n");
                    description.append(" * **Installed Version:** ").append(vulnerability.getInstalledVersion()).append("\n");
                    description.append(" * **Fix Version:** ").append(vulnerability.getFixedVersion()).append("\n");
                    description.append(" * **Summary:** ").append(vulnerability.getTitle()).append("\n");
                    description.append(" * **Info:** ").append(vulnerability.getDescription()).append("\n");
                    if (vulnerability.getReferences() != null && vulnerability.getReferences().size() > 0) {
                        description.append("\n\n**References:**\n");
                        for (String reference : vulnerability.getReferences()) {
                            if (reference.toLowerCase().startsWith("http")) {
                                description.append(" * [").append(reference).append("](").append(reference).append(")");
                            } else {
                                description.append(" * ").append(reference);
                            }
                            description.append("\n");
                        }
                    }
                    finding.setDescription(description.toString());
                    finding.addContext(vulnerability.getVulnerabilityId());
                    finding.addContext(vulnerability.getPackageName());
                    finding.addContext(vulnerability.getSeveritySource());
                    data.addFinding(finding);
                }
            }
        }
        return data;
    }

}
