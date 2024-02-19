package org.hyperledger.besu.crypto.pqc.metrics;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.CrystalsDilithiumSignature;
import org.hyperledger.besu.crypto.pqc.falcon.FalconSignature;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlusSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CSVWriter {

    private static final Logger LOG = LoggerFactory.getLogger(CSVWriter.class);
    private static CSVWriter instance = null;

    private static final String FILE_PATH = "/usr/app/PQCMetrics.csv";
    private File file;
    private FileWriter writer;
    private BufferedWriter bufferedWriter;
    private StringBuilder stringBuilder;

    private CSVWriter() {
        try {
            this.file = new File(CSVWriter.FILE_PATH);
            if (!this.file.exists()) {
                this.file.createNewFile();
                initializeTable();
            } else {
                initializeWriters();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    };

    private void initializeWriters() throws IOException {
        this.stringBuilder = new StringBuilder();
        this.writer = new FileWriter(CSVWriter.FILE_PATH, StandardCharsets.ISO_8859_1, true);
        this.bufferedWriter = new BufferedWriter(this.writer);
    }

    private void initializeTable() throws IOException {
        initializeWriters();
        this.bufferedWriter.write(
                "SECP(ns),SECP + DILITHIUM3(ns),DILITHIUM3 SIGNATURE LENGTH(bytes),SECP + SPHINCS(ns),SPHINCS SIGNATURE LENGTH(bytes),SECP + FALCON(ns),FALCON SIGNATURE LENGTH(bytes)\n");
        this.bufferedWriter.flush();
    }

    public void write(final long secpTime, final long dilithium3Time,
            final CrystalsDilithiumSignature dilithiumSignature, final long sphincsTime,
            final SphincsPlusSignature sphincsSignature, final long falconTime, final FalconSignature falconSignature) {
        try {
            String metricResult = stringBuilder
                    .append(secpTime + "," + dilithium3Time + "," + dilithiumSignature.getEncoded().length + ","
                            + sphincsTime + "," + sphincsSignature.getEncoded().length + "," + falconTime + ","
                            + falconSignature.getEncoded().length + "\n")
                    .toString();

            bufferedWriter.write(metricResult);
            bufferedWriter.flush();
            stringBuilder.setLength(0);
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    }

    public static void clean() {
        try {
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
}
