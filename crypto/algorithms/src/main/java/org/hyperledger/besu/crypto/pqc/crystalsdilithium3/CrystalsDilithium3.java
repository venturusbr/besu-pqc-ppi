package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;

public class CrystalsDilithium3 extends AbstractCrystalsDilithium3{
    @Override
    public String getAlgorithmName(){
        return "Dilithium";
    }

    @Override
    public String formatAlgorithmAndParamterTitle(){
        String parameterName =
        switch (SignatureAlgorithmFactory.getPqcParameterSpecIndex()) {
            case 0 -> "2";
            case 1 -> "3";
            case 2 -> "5";
            default -> "2";
        };
        return getAlgorithmName() + parameterName;
    }
}
