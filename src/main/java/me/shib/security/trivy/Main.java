package me.shib.security.trivy;

import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;

public final class Main {

    public static void main(String[] args) {
        try {
            String targetImageName = TrivyStewardEnv.TRIVY_TARGET_IMAGE.getAsString();
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
