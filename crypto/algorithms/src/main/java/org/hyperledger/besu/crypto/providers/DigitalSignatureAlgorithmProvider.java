package org.hyperledger.besu.crypto.providers;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.signature.Signature;

public class DigitalSignatureAlgorithmProvider implements DSAProvider{
    private final DigitalSignatureAlgorithmConfiguration config;
    private final KeyManager keyManager;

    public DigitalSignatureAlgorithmProvider(final DigitalSignatureAlgorithmConfiguration digitalSignatureAlgorithmConfig, final KeyConfiguration keyConfiguration){
        this.config = digitalSignatureAlgorithmConfig;
        this.keyManager = new KeyManager(keyConfiguration);
    }

    @Override
    public Signature signMessage(final Bytes data) {
        return config.getActiveDSA().sign(data, keyManager.getNodePrivateKey());
    }

    @Override
    public Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk) {
        return config.getActiveDSA().verify(data, signature, pk);
    }

    @Override
    public void loadNodeKeyPair(){
        PrivateKey sk = keyManager.loadPrivateKeyFromFile(config.getActiveDSA().getDsaParametersSet());
        keyManager.loadNodeKeyPairByPrivateKey(sk, config.getActiveDSA());
    }
}
