package org.hyperledger.besu.crypto.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

public class KeyManager {
    private final KeyExtractor keyExtractor;
    private NodeKeyPair nodeKeyPair;

    public KeyManager(){
        this.keyExtractor = new KeyExtractor();
    }

    public void loadNodeKeyPair(
        Bytes privateKeyBytes, 
        Bytes publicKeyBytes, 
        String firstAlgorithmName, 
        String secondAlgorithmName,
        boolean isHybrid,
        int firstPrivateKeyLength,
        int secondPrivateKeyLength,
        int firstPublicKeyLength,
        int secondPublicKeyLength
    ) {
        NodeKeyPair keyPair;
        if (!isHybrid) {
            keyPair = NodeKeyPair.create(privateKeyBytes, publicKeyBytes, firstAlgorithmName);
        } else {
            keyPair = NodeKeyPair.createHybrid(
                privateKeyBytes,
                publicKeyBytes,
                firstAlgorithmName,
                secondAlgorithmName,
                keyExtractor,
                firstPrivateKeyLength,
                secondPrivateKeyLength,
                firstPublicKeyLength,
                secondPublicKeyLength
            );
        }
        this.nodeKeyPair = keyPair;
    }

    public PrivateKey getNodePrivateKey(){
        return nodeKeyPair.getPrivateKey();
    }

    public PublicKey getNodePublicKey(){
        return nodeKeyPair.getPublicKey();
    }
}
