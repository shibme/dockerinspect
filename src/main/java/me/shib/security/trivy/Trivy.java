package me.shib.security.trivy;

import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

final class Trivy {

    private static transient final Gson gson = new Gson();
    private static transient final String toolName = "Trivy";
    private static transient final File trivyOutputFile = new File("trivy-out.json");

    private static String readFromFile(File file) {
        StringBuilder contentBuilder = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
            br.close();
        } catch (IOException ignored) {
        }
        return contentBuilder.toString();
    }

    private static TrivyReport getReport(File file) {
        String json = readFromFile(file);
        if (!json.isEmpty()) {
            TrivyReport[] reports = gson.fromJson(json, TrivyReport[].class);
            return reports[0];
        }
        return null;
    }

    static synchronized TrivyReport run(String imageName) throws TrivyException {
        try {
            String command = "trivy -f json -o " + trivyOutputFile.getName() + " " + imageName;
            CommandRunner commandRunner = new CommandRunner(command, toolName);
            commandRunner.execute();
            return getReport(trivyOutputFile);
        } catch (Exception e) {
            throw new TrivyException(e);
        }
    }

}
