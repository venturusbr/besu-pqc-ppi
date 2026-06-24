package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
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
    public DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId){
        return config.getEnabledDSA(dsaId);
    }

    @Override
    public DSAParametersSet getActiveDsaParametersSet() {
        final DigitalSignatureAlgorithm activeDSA = config.getActiveDSA();
        if (activeDSA != null) {
            return activeDSA.getDsaParametersSet();
        }
        return SignatureAlgorithmFactory.getInstance().getDsaParametersSet();
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
        keyManager.loadOrGenerateNodeKeyPair(config.getActiveDSA());
    }

    public List<String> getAccountsSupportedDSANames() {
        return config.getAccountsSupportedDSANames();
    }
}
