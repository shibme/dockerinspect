package me.shib.security.dockerinspect;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

final class Trivy {

    private static transient final Gson gson = new Gson();
    private static transient final String scanTool = "Trivy";
    private static transient final SimpleDateFormat outFilDateFormat =
            new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
    private static transient final File trivyCacheDir = new File("/root/.cache/");

    private static String readFromFile(File trivyOutputFile) {
        StringBuilder contentBuilder = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(trivyOutputFile));
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
            br.close();
        } catch (IOException ignored) {
        }
        return contentBuilder.toString();
    }

    private static List<TrivyResult> getResults(File trivyOutputFile, boolean osOnlyScan) throws DockerInspectException {
        String json = readFromFile(trivyOutputFile);
        System.out.println("Excution Report:\n" + json);
        if (!json.isEmpty()) {
            TrivyReport report = gson.fromJson(json, TrivyReport.class);
            List<TrivyResult> results = report.results;
            if (results != null) {
                if (osOnlyScan && results.size() > 1) {
                    throw new DockerInspectException("More than one result identified");
                }
                return results;
            }
        }
        return null;
    }

    private static void delete(File file) {
        if (file != null && file.exists()) {
            if (file.isDirectory()) {
                for (File f : file.listFiles()) {
                    delete(f);
                }
            }
            file.delete();
        }
    }

    private static void deleteDirContents(File dir) {
        if (dir != null && dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                delete(file);
            }
        }
    }

    static synchronized List<TrivyResult> run(String imageName, boolean osOnlyScan, boolean ignoreUnfixed, boolean clearCache) throws DockerInspectException {
        File trivyOutputFile = new File("trivy-out-" + outFilDateFormat.format(new Date()) + ".json");
        if (imageName == null) {
            throw new DockerInspectException("Image name required to run scan.");
        }
        try {
            StringBuilder command = new StringBuilder();
            command.append("trivy i --skip-db-update -f json -o ").append(trivyOutputFile.getName()).append(" ");
            if (osOnlyScan) {
                command.append("--vuln-type os ");
            }
            if (ignoreUnfixed) {
                command.append("--ignore-unfixed ");
            }
            command.append(imageName);
            CommandExecutor commandExecutor = new CommandExecutor(command.toString(), scanTool);
            commandExecutor.execute();
            List<TrivyResult> reports = getResults(trivyOutputFile, osOnlyScan);
            delete(trivyOutputFile);
            if (clearCache) {
                deleteDirContents(trivyCacheDir);
            }
            return reports;
        } catch (Exception e) {
            throw new DockerInspectException(e);
        }
    }

    static class TrivyReport {
        @SerializedName("Results")
        private List<TrivyResult> results;
    }

}
