package org.hyperledger.besu.crypto.config;

import java.util.HashMap;
import java.util.Map;

import org.hyperledger.besu.crypto.algorithms.hybrid.HybridStrongNestingConcatenation;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class SupportedAlgorithms {
    private static final Map<String, DigitalSignatureAlgorithm> DSA_ALGORITHMS = new HashMap<String, DigitalSignatureAlgorithm>();

    static {
        DSA_ALGORITHMS.put(DSAParametersSet.MLDSA44.getName(), new MLDSA(DSAParametersSet.MLDSA44));
        DSA_ALGORITHMS.put(DSAParametersSet.MLDSA65.getName(), new MLDSA(DSAParametersSet.MLDSA65));
        DSA_ALGORITHMS.put(DSAParametersSet.MLDSA87.getName(), new MLDSA(DSAParametersSet.MLDSA87));
        DSA_ALGORITHMS.put(DSAParametersSet.SECP256K1MLDSA44.getName(), new HybridStrongNestingConcatenation(new SECP256K1(), new MLDSA(DSAParametersSet.MLDSA44), DSAParametersSet.SECP256K1MLDSA44));
    }

    public DigitalSignatureAlgorithm getDSA(final String algorithmName){
        return DSA_ALGORITHMS.get(algorithmName);
    }
}
