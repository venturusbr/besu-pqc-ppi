package org.hyperledger.besu.crypto.pqc.metrics;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;

public class MetricWriters {
    private static CSVWriter signInstance = null;
    private static CSVWriter verifyInstance = null;

    public static void clean() {
        signInstance.clean();
        verifyInstance.clean();
    }

    public static String buildSignHeader(){
        String pqcAlgorithmName = SignatureAlgorithmFactory.getPqcAlgorithmName().toUpperCase();
        String header = pqcAlgorithmName + "(ns)," + pqcAlgorithmName + " + SECP(ns)\n";
        return header;
    }

    public static String buildVerifyHeader(){
        String pqcAlgorithmName = SignatureAlgorithmFactory.getPqcAlgorithmName().toUpperCase();
        String header = pqcAlgorithmName + "(ns)," + pqcAlgorithmName + " + SECP(ns)," + "isPqcValid\n";
        return header;
    }

    public static CSVWriter getSignInstance() {
        if (signInstance == null) {
            signInstance = new CSVWriter(buildSignHeader(), "sign");
        }
        return signInstance;
    }

    public static CSVWriter getVerifyInstance() {
        if (verifyInstance == null) {
            verifyInstance = new CSVWriter(buildVerifyHeader(), "verify");
        }
        return verifyInstance;
    }
}
