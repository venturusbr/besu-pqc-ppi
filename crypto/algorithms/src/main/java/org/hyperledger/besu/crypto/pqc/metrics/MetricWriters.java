package org.hyperledger.besu.crypto.pqc.metrics;

import java.util.function.BooleanSupplier;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

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
        String header = "DSASigningTime(ns)," + "SignatureBytes," + "Algorithm,"+ "FINALITY\n";
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

    /**
     * Runs a signature check and records it in the verify metrics.
     *
     * @param object what the signature is over, e.g. {@code tx}, {@code qbft-commit} or
     *     {@code discv4-packet}
     * @param algorithm the algorithm that verifies it
     * @param verification the check itself
     * @return whether the signature verified
     */
    public static boolean timeVerification(
            final String object,
            final DSAParametersSet algorithm,
            final BooleanSupplier verification) {
        final long start = System.nanoTime();
        final boolean isValid = verification.getAsBoolean();
        final long end = System.nanoTime();
        recordVerification(end - start, object, isValid, algorithm);
        return isValid;
    }

    /**
     * Writes a row of the verify metrics, in the columns {@link #buildVerifyHeader()} names.
     *
     * @param verificationTimeNanos how long the check took
     * @param object what the signature is over
     * @param isValid whether it verified
     * @param algorithm the algorithm that verified it
     */
    public static void recordVerification(
            final long verificationTimeNanos,
            final String object,
            final boolean isValid,
            final DSAParametersSet algorithm) {
        // Signatures are verified from many threads at once, so each line is built locally.
        getVerifyInstance().write(
            verifyMetricsLine(verificationTimeNanos, object, isValid, algorithm));
    }

    static String verifyMetricsLine(
            final long verificationTimeNanos,
            final String object,
            final boolean isValid,
            final DSAParametersSet algorithm) {
        return verificationTimeNanos
            + ","
            + object
            + ","
            + (isValid ? "yes" : "no")
            + ","
            + algorithm.getName()
            + "\n";
    }
}
