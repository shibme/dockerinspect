package me.shib.security.trivy;

import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;

public final class Main {

    private static transient final String TRIVY_TARGET_IMAGE = "TRIVY_TARGET_IMAGE";

    public static void main(String[] args) {
        try {
            String targetImageName = System.getenv(TRIVY_TARGET_IMAGE);
            if (args.length > 0) {
                targetImageName = args[0];
            }
            TrivyReport report = Trivy.run(targetImageName);
            StewardData stewardData = TSConvert.toStewardData(report);
            Steward.process(stewardData, StewardConfig.getConfig());
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
