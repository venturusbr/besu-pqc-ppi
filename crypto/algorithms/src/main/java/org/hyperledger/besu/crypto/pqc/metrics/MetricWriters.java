package org.hyperledger.besu.crypto.pqc.metrics;

public class MetricWriters {
    private static CSVWriter signInstance = null;
    private static CSVWriter verifyInstance = null;

    public static void clean() {
        signInstance.clean();
        verifyInstance.clean();
    }

    public static String buildSignHeader(){
        String header = "DSASigningTime(ns)," + "SignatureBytes," + "Object," + "Algorithm,"+ "FINALITY\n";
        return header;
    }

    public static String buildVerifyHeader(){
        String header = "DSAVerificationTime(ns)," + "Object," + "isSignatureValid," + "Algorithm\n";
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
