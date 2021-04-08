package me.shib.security.dockerinspect;

import me.shib.steward.Steward;
import me.shib.steward.StewardData;
import me.shib.steward.StewardException;

import java.util.List;

public final class Main {

    public static void main(String[] args) throws DockerInspectException, StewardException {
        DockerInspectEnv.validateEnv();
        String targetImageName = DockerInspectEnv.DOCKERINSPECT_TARGET_IMAGE.getAsString();
        boolean osOnlyScan = !DockerInspectEnv.DOCKERINSPECT_DEPENDENCY_SCAN.getAsBoolean();
        boolean ignoreUnfixed = DockerInspectEnv.DOCKERINSPECT_IGNORE_UNFIXED.getAsBoolean();
        boolean clearCache = DockerInspectEnv.DOCKERINSPECT_CLEAR_CACHE.getAsBoolean();
        List<TrivyReport> reports = Trivy.run(targetImageName, osOnlyScan, ignoreUnfixed, clearCache);
        StewardData stewardData = TSConvert.toStewardData(reports);
        Steward.process(stewardData);
        System.exit(0);
    }
}
