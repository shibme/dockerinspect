package me.shib.security.trivy;

import me.shib.steward.StewardData;
import me.shib.steward.StewardFinding;

class TSConvert {

    private static final transient String cveBaseURL = "https://nvd.nist.gov/vuln/detail/";
    private static final transient String toolName = "Trivy";

    private static String getUrlForCVE(String cve) throws TrivyException {
        if (cve != null && cve.toUpperCase().startsWith("CVE")) {
            return cveBaseURL + cve;
        }
        throw new TrivyException("CVE provided is not valid");
    }

    static StewardData toStewardData(TrivyReport report, String projectName) {
        if (projectName == null || projectName.isEmpty()) {
            projectName = report.getTarget();
        }
        StewardData data = new StewardData(projectName, toolName);
        data.addContext(report.getType());
        data.addContext(projectName);
        for (Vulnerability vulnerability : report.getVulnerabilities()) {
            String title = "Vulnerability [" + vulnerability.getVulnerabilityId() + "] found in " +
                    vulnerability.getPackageName() + " of " + report.getTarget();
            StewardFinding finding = new StewardFinding(title,
                    vulnerability.getSeverity().getPriority());
            StringBuilder description = new StringBuilder();
            description.append("A vulnerable component (**").append(vulnerability.getPackageName())
                    .append("-").append(vulnerability.getInstalledVersion()).append("**) was found in ")
                    .append("**").append(report.getTarget()).append("**.\n\n");
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
        return data;
    }

    static StewardData toStewardData(TrivyReport report) {
        return toStewardData(report, null);
    }

}
