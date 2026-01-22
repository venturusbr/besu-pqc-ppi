package org.hyperledger.besu.crypto.pqc.metrics;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;

public class MetricWriters {
    private static CSVWriter signInstance = null;
    private static CSVWriter verifyInstance = null;

    public static void clean() {
        signInstance.clean();
        verifyInstance.clean();
    }

    public static String buildSignHeader(){
        String pqcAlgorithmNameAndParameter = SignatureAlgorithmFactory.getPqcGenericInstance().formatAlgorithmAndParameterTitle().toUpperCase();
        String header = pqcAlgorithmNameAndParameter + "(ns)," + pqcAlgorithmNameAndParameter + " + SECP(ns)," + "PQC_SIGNATURE_LENGTH(bytes)," + "SECP_SIGNATURE_LENGTH(bytes)," + "FINALITY\n";
        return header;
    }

    public static String buildVerifyHeader(){
        String pqcAlgorithmNameAndParameter = SignatureAlgorithmFactory.getPqcGenericInstance().formatAlgorithmAndParameterTitle().toUpperCase();
        String header = pqcAlgorithmNameAndParameter + "(ns)," + pqcAlgorithmNameAndParameter + " + SECP(ns)," + "isPqcValid\n";
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
