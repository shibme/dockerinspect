package me.shib.security.trivy;

import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

final class Trivy {

    private static transient final Gson gson = new Gson();
    private static transient final String toolName = "Trivy";
    private static transient final SimpleDateFormat outFilDateFormat =
            new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
    private static transient final File trivyOutputFile =
            new File("trivy-out-" + outFilDateFormat.format(new Date()) + ".json");

    private static String readFromFile() {
        StringBuilder contentBuilder = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(Trivy.trivyOutputFile));
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
            br.close();
        } catch (IOException ignored) {
        }
        return contentBuilder.toString();
    }

    private static List<TrivyReport> getReports(boolean osOnlyScan) throws TrivyException {
        String json = readFromFile();
        if (!json.isEmpty()) {
            TrivyReport[] reports = gson.fromJson(json, TrivyReport[].class);
            if (osOnlyScan && reports.length > 1) {
                System.out.println("Report JSON:");
                System.out.println(json);
                throw new TrivyException("More than one reports identified");
            }
            return Arrays.asList(reports);
        }
        return null;
    }

    static synchronized List<TrivyReport> run(String imageName, boolean osOnlyScan) throws TrivyException {
        if (imageName == null) {
            throw new TrivyException("Image name required to run scan.");
        }
        try {
            StringBuilder command = new StringBuilder();
            command.append("trivy -f json -o ").append(trivyOutputFile.getName()).append(" ");
            if (osOnlyScan) {
                command.append("--vuln-type os ");
            }
            command.append(imageName);
            CommandRunner commandRunner = new CommandRunner(command.toString(), toolName);
            commandRunner.execute();
            return getReports(osOnlyScan);
        } catch (Exception e) {
            throw new TrivyException(e);
        }
    }

}
