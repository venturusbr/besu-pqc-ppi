package org.hyperledger.besu.crypto.pqc.metrics;

public class MetricWriters {
    private static CSVWriter signInstance = null;
    private static CSVWriter verifyInstance = null;
    private static CSVWriter pkrInstance = null;

    public static void clean() {
        signInstance.clean();
        verifyInstance.clean();
        pkrInstance.clean();
    }

    public static String buildSignHeader(){
        String header = "DSASigningTime(ns)," + "SignatureBytes," + "Object," + "Algorithm,"+ "FINALITY\n";
        return header;
    }

    public static String buildVerifyHeader(){
        String header = "DSAVerificationTime(ns)," + "Object," + "isSignatureValid," + "Algorithm\n";
        return header;
    }

    public static String buildPkrHeader(){
        String header = "PKRTime(ns)," + "Object";
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

    public static CSVWriter getPkrInstance() {
        if(pkrInstance == null){
            pkrInstance = new CSVWriter(buildPkrHeader(), "pkr");
        }
        return pkrInstance;
    }
}
