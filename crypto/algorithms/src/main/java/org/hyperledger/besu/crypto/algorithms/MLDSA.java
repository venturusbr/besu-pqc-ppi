package org.hyperledger.besu.crypto.algorithms;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class MLDSA implements DigitalSignatureAlgorithm{
    DSAParametersSet mldsaParameters;

    //TODO: MLDSA implementation
    public MLDSA(DSAParametersSet mldsaParameters){
        this.mldsaParameters = mldsaParameters;
    }
}
