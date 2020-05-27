package me.shib.security.trivy;

import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;
import me.shib.steward.StewardException;

import java.util.List;

public final class Main {

    public static void main(String[] args) throws TrivyException, StewardException {
        TrivyStewardEnv.validateEnv();
        String targetImageName = TrivyStewardEnv.TS_TARGET_IMAGE.getAsString();
        boolean osOnlyScan = !TrivyStewardEnv.TS_DEPENDENCY_SCAN.getAsBoolean();
        List<TrivyReport> reports = Trivy.run(targetImageName, osOnlyScan);
        StewardData stewardData = TSConvert.toStewardData(reports);
        Steward.process(stewardData, StewardConfig.getConfig());
    }
}
