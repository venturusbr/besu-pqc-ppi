package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.signature.Signature;

public class DigitalSignatureAlgorithmProvider implements NodeKeyProvider, KeyManagementProvider, VerifierProvider {
    private final DigitalSignatureAlgorithmConfiguration config;
    private final KeyManager keyManager;

    public DigitalSignatureAlgorithmProvider(
            final DigitalSignatureAlgorithmConfiguration digitalSignatureAlgorithmConfig,
            final KeyConfiguration keyConfiguration) {
        this.config = digitalSignatureAlgorithmConfig;
        this.keyManager = new KeyManager(keyConfiguration);
    }

    @Override
    public DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId) {
        return config.getEnabledDSA(dsaId);
    }

    @Override
    public DSAParametersSet getActiveDsaParametersSet() {
        final DigitalSignatureAlgorithm activeDSA = config.getNodeActiveDSA();
        if (activeDSA != null) {
            return activeDSA.getDsaParametersSet();
        }
        return SignatureAlgorithmFactory.getInstance().getDsaParametersSet();
    }

    @Override
    public Signature sign(final Bytes32 data) {
        return config.getNodeActiveDSA().sign(data, keyManager.getNodePrivateKey());
    }

    @Override
    public Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk) {
        return config.getNodeActiveDSA().verify(data, signature, pk);
    }

    @Override
    public KeyPair generateKeyPair(final DSAParametersSet dsaParams) {
        return config.getSupportedDSA(dsaParams.getName()).generateNodeKeyPair();
    }

    @Override
    public void loadNodeKeyPair() {
        keyManager.loadNodeKeyPairByPrivateKey(config.getNodeActiveDSA());
    }

    @Override
    public List<String> getAccountsSupportedDSANames() {
        return config.getAccountsSupportedDSANames();
    }

    @Override
    public PublicKey getPublicKey() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPublicKey'");
    }

    @Override
    public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'calculateECDHKeyAgreement'");
    }
}
