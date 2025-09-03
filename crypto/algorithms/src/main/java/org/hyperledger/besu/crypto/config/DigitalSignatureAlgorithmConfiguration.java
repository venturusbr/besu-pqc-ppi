package org.hyperledger.besu.crypto.config;

import java.security.InvalidAlgorithmParameterException;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;

public class DigitalSignatureAlgorithmConfiguration {
    private final SupportedAlgorithms supportedAlgorithms;
    private DigitalSignatureAlgorithm activeDSA;

    DigitalSignatureAlgorithmConfiguration(){
        this.supportedAlgorithms = new SupportedAlgorithms();
        this.activeDSA = null;
    }

    public void setActiveDSA(String algorithmName) throws InvalidAlgorithmParameterException{
        DigitalSignatureAlgorithm maybeDsa = supportedAlgorithms.getDSA(algorithmName);

        if(maybeDsa == null){
            throw new InvalidAlgorithmParameterException("the algorithm name provided is not supported");
        }

        this.activeDSA = maybeDsa;
    }

    public DigitalSignatureAlgorithm getActiveDSA(){
        return activeDSA;
    }
}
