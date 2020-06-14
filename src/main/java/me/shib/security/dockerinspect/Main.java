package me.shib.security.dockerinspect;

import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;
import me.shib.steward.StewardException;

import java.util.List;

public final class Main {

    public static void main(String[] args) throws DockerInspectException, StewardException {
        DocerInspectEnv.validateEnv();
        String targetImageName = DocerInspectEnv.DOCKERINSPECT_TARGET_IMAGE.getAsString();
        boolean osOnlyScan = !DocerInspectEnv.DOCKERINSPECT_DEPENDENCY_SCAN.getAsBoolean();
        List<TrivyReport> reports = Trivy.run(targetImageName, osOnlyScan);
        StewardData stewardData = TSConvert.toStewardData(reports);
        Steward.process(stewardData, StewardConfig.getConfig());
    }
}
