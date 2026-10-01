package org.hyperledger.besu.crypto.config;

import java.util.function.Supplier;

import com.google.common.collect.ImmutableMap;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.hybrid.HybridStrongNestingConcatenation;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class SupportedAlgorithms {

    private static final ImmutableMap<String, Supplier<DigitalSignatureAlgorithm>>
        DSA_ALGORITHMS =
            ImmutableMap.of(
                DSAParametersSet.SECP256K1.getName(),
                SECP256K1::new,
                DSAParametersSet.MLDSA44.getName(),
                () -> new MLDSA(DSAParametersSet.MLDSA44),
                DSAParametersSet.MLDSA65.getName(),
                () -> new MLDSA(DSAParametersSet.MLDSA65),
                DSAParametersSet.MLDSA87.getName(),
                () -> new MLDSA(DSAParametersSet.MLDSA87),
                DSAParametersSet.FALCON512.getName(),
                () -> new Falcon(DSAParametersSet.FALCON512),
                DSAParametersSet.SECP256K1MLDSA44.getName(),
                () ->
                    new HybridStrongNestingConcatenation(
                        new SECP256K1(),
                        new MLDSA(DSAParametersSet.MLDSA44),
                        DSAParametersSet.SECP256K1MLDSA44),
                DSAParametersSet.SECP256K1FALCON512.getName(),
                () ->
                    new HybridStrongNestingConcatenation(
                        new SECP256K1(),
                        new Falcon(DSAParametersSet.FALCON512),
                        DSAParametersSet.SECP256K1FALCON512));

    public Supplier<DigitalSignatureAlgorithm> getDSAByName(final String algorithmName) {
        return DSA_ALGORITHMS.get(algorithmName);
    }

    public Boolean supports(final String algorithmName) {
        return DSA_ALGORITHMS.containsKey(algorithmName);
    }
}