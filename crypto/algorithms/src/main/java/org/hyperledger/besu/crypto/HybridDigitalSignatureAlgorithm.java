package org.hyperledger.besu.crypto;

public interface HybridDigitalSignatureAlgorithm extends DigitalSignatureAlgorithm{
    DigitalSignatureAlgorithm getFirstAlgorithm();
    DigitalSignatureAlgorithm getSecondAlgorithm();
}
