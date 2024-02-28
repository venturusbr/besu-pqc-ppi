package org.hyperledger.besu.crypto.pqc.metrics;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class MetricWriter {

    private final Logger LOG = LoggerFactory.getLogger(getSubClass());
    private static final String HOME_PATH = "/usr/app/";
    private final String FILE_PATH;
    private FileWriter writer;
    private BufferedWriter bufferedWriter;
    private StringBuilder stringBuilder;
    private ExecutorService executor;

    private MetricWriter(String pathName) {
        this.stringBuilder = new StringBuilder();
        FILE_PATH = buildPath(pathName);
        try {
            File file = new File(FILE_PATH);
            this.executor = Executors.newCachedThreadPool();
            if (file.exists()) {
                file.createNewFile();
                initializeTable();
            } else {
                initializeWriters();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    };

    private String buildPath(String ref) {
        String path = stringBuilder.append(HOME_PATH + SignatureAlgorithmFactory.getPqcAlgorithmName() + "-" + ref + ".csv")
                .toString();
        stringBuilder.setLength(0);
        return path;
    }

    private void initializeWriters() throws IOException {
        this.writer = new FileWriter(SIGN_FILE_PATH, StandardCharsets.ISO_8859_1, true);
        this.bufferedWriter = new BufferedWriter(this.writer);
    }

    private void initializeTable(String header) throws IOException {
        initializeWriters();
        String pqcAlgorithmName = SignatureAlgorithmFactory.getPqcAlgorithmName().toUpperCase();
        String header = stringBuilder.append(pqcAlgorithmName + "(ns)," + pqcAlgorithmName + " + SECP(ns)").toString();
        this.bufferedWriter.write(header);
        this.bufferedWriter.flush();
        stringBuilder.setLength(0);
    }

    public void write(final long secpTime, final long pqcTime) {
        executor.execute(new Register(secpTime, pqcTime));
    }

    public static void clean() {
        try {
            instance.executor.shutdown();
            instance.writer.close();
            instance.bufferedWriter.close();
            instance = null;
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    }

    public static CSVWriter getInstance() {
        if (instance == null) {
            instance = new CSVWriter();
        }
        return instance;
    }

    protected abstract Class getSubClass();

    private class Register implements Runnable {
        private final Long secpTime;
        private final Long pqcTime;

        public Register(final Long secpTime, final Long pqcTime) {
            this.secpTime = secpTime;
            this.pqcTime = pqcTime;
        }

        @Override
        public void run() {
            try {
                String metricResult = stringBuilder
                        .append(pqcTime + "," + (pqcTime + secpTime) + "\n")
                        .toString();

                bufferedWriter.write(metricResult);
                bufferedWriter.flush();
                stringBuilder.setLength(0);
            } catch (IOException e) {
                LOG.info(e.getMessage());
            }
        }
    }
}
