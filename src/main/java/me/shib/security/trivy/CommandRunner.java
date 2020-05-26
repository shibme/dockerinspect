package me.shib.security.trivy;

import java.io.*;

final class CommandRunner {

    private final transient String command;
    private final transient StreamProcessor inputProcessor;
    private final transient StreamProcessor errorProcessor;
    private final transient StringBuilder streamContent;
    private final transient String label;
    private final transient File workDir;
    private transient Process process;

    CommandRunner(String command, File workDir, String label) {
        this.command = command;
        this.workDir = workDir;
        this.inputProcessor = new StreamProcessor(this, StreamType.INPUT);
        this.errorProcessor = new StreamProcessor(this, StreamType.ERROR);
        this.streamContent = new StringBuilder();
        this.inputProcessor.start();
        this.errorProcessor.start();
        this.label = label.toUpperCase();
    }

    CommandRunner(String command, String label) {
        this(command, null, label);
    }

    private synchronized void addLine(String line) {
        streamContent.append(line).append("\n");
        System.out.println("[" + label + "] " + line);
    }

    private Process getProcess() {
        return this.process;
    }

    void execute() throws IOException, InterruptedException {
        if (workDir != null) {
            process = Runtime.getRuntime().exec(command, null, workDir);
        } else {
            process = Runtime.getRuntime().exec(command);
        }
        this.inputProcessor.join();
        this.errorProcessor.join();
        process.waitFor();
    }

    private enum StreamType {
        INPUT, ERROR
    }

    private static final class StreamProcessor extends Thread {

        private final CommandRunner commandRunner;
        private final StreamType type;

        private StreamProcessor(CommandRunner commandRunner, StreamType type) {
            this.commandRunner = commandRunner;
            this.type = type;
        }

        private void processContent(InputStream inputStream) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                commandRunner.addLine(line);
            }
            reader.close();
        }

        @Override
        public void run() {
            Process process;
            while ((process = commandRunner.getProcess()) == null) {
                try {
                    Thread.sleep(5);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            InputStream inputStream = null;
            if (type == StreamType.INPUT) {
                inputStream = process.getInputStream();
            } else if (type == StreamType.ERROR) {
                inputStream = process.getErrorStream();
            }
            try {
                processContent(inputStream);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
