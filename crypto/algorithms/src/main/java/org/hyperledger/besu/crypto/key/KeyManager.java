package org.hyperledger.besu.crypto.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;

public class KeyManager {
    private final KeyExtractor keyExtractor;
    private final DigitalSignatureAlgorithmConfiguration dsaConfig;
    private NodeKeyPair nodeKeyPair;

    public KeyManager(DigitalSignatureAlgorithmConfiguration dsaConfig) {
        this.keyExtractor = new KeyExtractor();
        this.dsaConfig = dsaConfig;
    }

    public void buildNodeKeyPair(
            Bytes privateKeyBytes,
            Bytes publicKeyBytes) {
        Boolean isHybrid = dsaConfig.getActiveDSA() instanceof HybridDigitalSignatureAlgorithm;
        if (isHybrid) {
            buildHybridNodeKeyPair(privateKeyBytes, publicKeyBytes);
            return;
        }
        this.nodeKeyPair = NodeKeyPair.create(privateKeyBytes, publicKeyBytes,
        dsaConfig.getActiveDSA().getDsaParametersSet().getName());
    }

    private void buildHybridNodeKeyPair(Bytes privateKeyBytes, Bytes publicKeyBytes){
        HybridDigitalSignatureAlgorithm hybridDSA = (HybridDigitalSignatureAlgorithm) dsaConfig.getActiveDSA();
        DSAParametersSet firstAlgorithmParams = hybridDSA.getFirstAlgorithm().getDsaParametersSet();
        DSAParametersSet secondAlgorithmParams = hybridDSA.getSecondAlgorithm().getDsaParametersSet();

        PrivateKey firstSk = keyExtractor.extractPrivateKeyAtOffset(privateKeyBytes, 0, firstAlgorithmParams.getPrivateKeyLength(), firstAlgorithmParams.getName(), "RAW");
        PrivateKey secondSk = keyExtractor.extractPrivateKeyAtOffset(privateKeyBytes, firstAlgorithmParams.getPrivateKeyLength(), secondAlgorithmParams.getPrivateKeyLength(), secondAlgorithmParams.getName(), "RAW");

        PublicKey firstPk = keyExtractor.extractPublicKeyAtOffset(publicKeyBytes, 0, firstAlgorithmParams.getPublicKeyLength(), firstAlgorithmParams.getName(), "RAW");

        PublicKey secondPk = keyExtractor.extractPublicKeyAtOffset(publicKeyBytes, firstAlgorithmParams.getPublicKeyLength(), secondAlgorithmParams.getPublicKeyLength(), secondAlgorithmParams.getName(), "RAW");

        NodeKeyPair keyPair = NodeKeyPair.createHybrid(
                firstSk,
                secondSk,
                firstPk,
                secondPk);
        this.nodeKeyPair = keyPair;
    }

    public PrivateKey getNodePrivateKey() {
        return nodeKeyPair.getPrivateKey();
    }

    public PublicKey getNodePublicKey() {
        return nodeKeyPair.getPublicKey();
    }
}
