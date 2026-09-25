package org.hyperledger.besu.crypto.pqc.metrics;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CSVWriter {

    private static final Logger LOG = LoggerFactory.getLogger(CSVWriter.class);

    private static final String HOME_PATH = "/usr/app/";
    private final StringBuilder stringBuilder;
    private final String FILE_PATH;

    private FileWriter writer;
    private BufferedWriter bufferedWriter;
    private ExecutorService executor;

    public CSVWriter(final String header, final String filePath) {
        this.stringBuilder = new StringBuilder();
        FILE_PATH = buildPath(filePath);
        try {
            File signFile = new File(FILE_PATH);
            this.executor = Executors.newSingleThreadExecutor();
            if (!signFile.exists()) {
                signFile.createNewFile();
                initializeTable(header);
            } else {
                initializeWriters();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    };

    private String buildPath(final String ref) {
        String path = stringBuilder
                .append(HOME_PATH + ref + "-metrics.csv")
                .toString();
        stringBuilder.setLength(0);
        return path;
    }

    private void initializeWriters() throws IOException {
        this.writer = new FileWriter(FILE_PATH, StandardCharsets.ISO_8859_1, true);
        this.bufferedWriter = new BufferedWriter(this.writer);
    }

    private void initializeTable(final String header) throws IOException {
        initializeWriters();
        this.bufferedWriter.write(header);
        this.bufferedWriter.flush();
        stringBuilder.setLength(0);
    }

    public void write(final String data) {
        // The metrics file may not have opened, and clean() may already have shut the executor
        // down. Metrics are best effort, so drop the sample instead of failing the caller.
        if (bufferedWriter == null || executor == null || executor.isShutdown()) {
            return;
        }
        executor.execute(new Register(data));
    }

    public void clean() {
        if (executor != null) {
            executor.shutdown();
        }
        // Closing the buffered writer flushes and closes the underlying file writer.
        try {
            if (bufferedWriter != null) {
                bufferedWriter.close();
            } else if (writer != null) {
                writer.close();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    }

    private class Register implements Runnable {
        private final String data;

        public Register(final String data) {
            this.data = data;
        }

        @Override
        public void run() {
            if (bufferedWriter == null) {
                return;
            }
            try {
                bufferedWriter.write(data);
                bufferedWriter.flush();
                stringBuilder.setLength(0);
            } catch (IOException e) {
                LOG.info(e.getMessage());
            }
        }
    }
}
