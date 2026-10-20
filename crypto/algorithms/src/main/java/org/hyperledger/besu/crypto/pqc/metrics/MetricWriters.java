package org.hyperledger.besu.crypto.pqc.metrics;

public class MetricWriters {
    private static CSVWriter signInstance = null;
    private static CSVWriter verifyInstance = null;
    private static CSVWriter pkrInstance = null;

    // Writers are created by whichever thread first records a sample, and several do at once, so
    // creating and closing them is synchronized: an unsynchronized check-then-create could open
    // the same file twice and lose one writer's samples.
    public static synchronized void clean() {
        // The writers are created on first use, so a run that never signed, verified or recovered
        // a key has none of them.
        if (signInstance != null) {
            signInstance.clean();
        }
        if (verifyInstance != null) {
            verifyInstance.clean();
        }
        if (pkrInstance != null) {
            pkrInstance.clean();
        }
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
        String header = "PKRTime(ns)," + "Object\n";
        return header;
    }

    public static synchronized CSVWriter getSignInstance() {
        if (signInstance == null) {
            signInstance = new CSVWriter(buildSignHeader(), "sign");
        }
        return signInstance;
    }

    public static synchronized CSVWriter getVerifyInstance() {
        if (verifyInstance == null) {
            verifyInstance = new CSVWriter(buildVerifyHeader(), "verify");
        }
        return verifyInstance;
    }

    public static synchronized CSVWriter getPkrInstance() {
        if(pkrInstance == null){
            pkrInstance = new CSVWriter(buildPkrHeader(), "pkr");
        }
        return pkrInstance;
    }
}
