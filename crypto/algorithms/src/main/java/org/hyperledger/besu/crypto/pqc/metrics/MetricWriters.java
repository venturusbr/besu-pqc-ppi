package org.hyperledger.besu.crypto.pqc.metrics;

import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import com.google.common.base.Splitter;

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
        String header = "DSASigningTime(ns)," + "Algorithm,"+ "Context\n";
        return header;
    }

    public static String buildVerifyHeader(){
        String header = "DSAVerificationTime(ns)," + "isSignatureValid," + "Algorithm," + "Context\n";
        return header;
    }

    public static String buildPkrHeader(){
        String header = "PKRTime(ns)," + "isRecovered," + "Algorithm," + "Context\n";
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
     * Runs a signature check and records it in the verify metrics. A check that throws is
     * recorded as not valid, and the exception is passed on.
     *
     * @param context what the signature is over, e.g. {@code tx}, {@code qbft-commit} or
     *     {@code discv4-packet}
     * @param algorithm the algorithm as the metrics name it, see {@link #verifiedAlgorithm}
     * @param verification the check itself
     * @return whether the signature verified
     */
    public static boolean timeVerification(
            final String context,
            final String algorithm,
            final BooleanSupplier verification) {
        final long start = System.nanoTime();
        final boolean isValid;
        try {
            isValid = verification.getAsBoolean();
        } catch (final RuntimeException e) {
            recordVerification(System.nanoTime() - start, context, false, algorithm);
            throw e;
        }
        recordVerification(System.nanoTime() - start, context, isValid, algorithm);
        return isValid;
    }

    /**
     * Writes a row of the verify metrics, in the columns {@link #buildVerifyHeader()} names.
     *
     * @param verificationTimeNanos how long the check took
     * @param context what the signature is over
     * @param isValid whether it verified
     * @param algorithm the algorithm as the metrics name it, see {@link #verifiedAlgorithm}
     */
    public static void recordVerification(
            final long verificationTimeNanos,
            final String context,
            final boolean isValid,
            final String algorithm) {
        // Signatures are verified from many threads at once, so each line is built locally.
        getVerifyInstance().write(
            verifyMetricsLine(verificationTimeNanos, context, isValid, algorithm));
    }

    /**
     * Runs a public key recovery and records it in the PKR metrics. A recovery that comes back
     * empty or throws is recorded as not recovered, and the exception is passed on.
     *
     * @param context what the signature is over, e.g. {@code tx}, {@code qbft-commit} or
     *     {@code discv4-packet}
     * @param algorithm the algorithm as the metrics name it, see {@link #recoveredAlgorithm}
     * @param recovery the recovery itself
     * @param <T> the key it yields
     * @return the recovered key, or empty when none could be recovered
     */
    public static <T> Optional<T> timeRecovery(
            final String context,
            final String algorithm,
            final Supplier<Optional<T>> recovery) {
        final long start = System.nanoTime();
        final Optional<T> recovered;
        try {
            recovered = recovery.get();
        } catch (final RuntimeException e) {
            recordRecovery(System.nanoTime() - start, context, false, algorithm);
            throw e;
        }
        recordRecovery(System.nanoTime() - start, context, recovered.isPresent(), algorithm);
        return recovered;
    }

    /**
     * Writes a row of the PKR metrics, in the columns {@link #buildPkrHeader()} names.
     *
     * @param recoveryTimeNanos how long the recovery took
     * @param context what the signature is over
     * @param isRecovered whether a key was recovered
     * @param algorithm the algorithm as the metrics name it, see {@link #recoveredAlgorithm}
     */
    public static void recordRecovery(
            final long recoveryTimeNanos,
            final String context,
            final boolean isRecovered,
            final String algorithm) {
        getPkrInstance().write(pkrMetricsLine(recoveryTimeNanos, context, isRecovered, algorithm));
    }

    /**
     * The algorithm of a signature check as the verify metrics name it. A hybrid is named in full,
     * with the half that was verified in parentheses, e.g. {@code SECP256K1-(MLDSA44)}: verifying
     * a hybrid leaves any half that supports key recovery to the recovery, which the PKR metrics
     * record.
     *
     * @param dsa the algorithm whose verify was called
     * @return its name for the verify metrics
     */
    public static String verifiedAlgorithm(final DigitalSignatureAlgorithm dsa) {
        if (!(dsa instanceof HybridDigitalSignatureAlgorithm hybrid)) {
            return dsa.getDsaParametersSet().getName();
        }
        final List<DSAParametersSet> verified =
            Stream.of(hybrid.getFirstAlgorithm(), hybrid.getSecondAlgorithm())
                .filter(half -> !(half instanceof PublicKeyRecoverable))
                .map(DigitalSignatureAlgorithm::getDsaParametersSet)
                .collect(Collectors.toList());
        return verified.size() == 1
            ? highlight(dsa.getDsaParametersSet(), verified.get(0))
            : dsa.getDsaParametersSet().getName();
    }

    /**
     * The algorithm of a key recovery as the PKR metrics name it. A hybrid is named in full, with
     * the half whose key was recovered in parentheses, e.g. {@code (SECP256K1)-MLDSA44}.
     *
     * @param signed the algorithm the signature was made with, hybrid or not
     * @param recovering the algorithm that recovered the key: {@code signed} itself or one of its
     *     halves
     * @return its name for the PKR metrics
     */
    public static String recoveredAlgorithm(
            final DSAParametersSet signed, final DSAParametersSet recovering) {
        return highlight(signed, recovering);
    }

    /** The name of {@code whole} with the {@code part} that did the work in parentheses. */
    static String highlight(final DSAParametersSet whole, final DSAParametersSet part) {
        if (whole == part) {
            return whole.getName();
        }
        // A hybrid is named after its halves, joined by a hyphen.
        final List<String> halves = Splitter.on('-').splitToList(whole.getName());
        if (!halves.contains(part.getName())) {
            return whole.getName();
        }
        return halves.stream()
            .map(half -> half.equals(part.getName()) ? "(" + half + ")" : half)
            .collect(Collectors.joining("-"));
    }

    static String pkrMetricsLine(
            final long recoveryTimeNanos,
            final String context,
            final boolean isRecovered,
            final String algorithm) {
        return recoveryTimeNanos
            + ","
            + (isRecovered ? "yes" : "no")
            + ","
            + algorithm
            + ","
            + context
            + "\n";
    }

    static String verifyMetricsLine(
            final long verificationTimeNanos,
            final String context,
            final boolean isValid,
            final String algorithm) {
        return verificationTimeNanos
            + ","
            + (isValid ? "yes" : "no")
            + ","
            + algorithm
            + ","
            + context
            + "\n";
    }
}
