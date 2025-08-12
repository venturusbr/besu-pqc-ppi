package org.hyperledger.besu.crypto.providers;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.signature.Signature;

public class DigitalSignatureAlgorithmProvider implements DSAProvider{
    DigitalSignatureAlgorithmConfiguration config;
    DigitalSignatureAlgorithm activeSignatureAlgorithm;
    KeyManager keyManager;

    public DigitalSignatureAlgorithmProvider(DigitalSignatureAlgorithm digitalSignatureAlgorithm, KeyManager keyManager){
        this.activeSignatureAlgorithm = digitalSignatureAlgorithm;
        this.keyManager = keyManager;
    }

    @Override
    public Signature signMessage(Bytes data) {
        // TODO
    }

    @Override
    public Boolean verifySignature(Bytes data, Signature signature) {
        // TODO
    }

    @Override
    public NodeKeyPair generateKeyPair(){
        // TODO
    }

    public void loadNodeKeyPair(Bytes privateKeyBytes, Bytes publicKeyBytes){
        keyManager.loadNodeKeyPair(privateKeyBytes, publicKeyBytes, activeSignatureAlgorithm.getAlgorithmName());
    }
}
