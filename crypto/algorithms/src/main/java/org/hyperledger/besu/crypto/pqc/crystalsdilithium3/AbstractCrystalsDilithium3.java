package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;

public abstract class AbstractCrystalsDilithium3 implements DilithiumSignatureAlgorithm {

    private final DilithiumParameterSpec DILITHIUM_PARAMETER_SPEC = DilithiumParameterSpec.dilithium3;

    protected KeyPairGenerator keyPairGenerator;

    @Override
    public Dilithium3KeyPair generateKeyPair() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("Dilithium");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        Dilithium3KeyPair keyPair = Dilithium3KeyPair.generateCrystalsDilithiumPair(keyPairGenerator,
                DILITHIUM_PARAMETER_SPEC);

        return keyPair;
    }

    @Override
    public Dilithium3KeyPair createDilithium3KeyPair(final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey){
        return Dilithium3KeyPair.createKeyPair(privateKey, publicKey);
    }

    @Override
    public Dilithium3PrivateKey createPrivateKey(final String hex){
        byte[] encoded = Dilithium3PrivateKey.hexToBytes(hex);
        return Dilithium3PrivateKey.create(encoded);
    }

    @Override
    public Dilithium3PublicKey createPublicKey(final String hex){
        byte[] encoded = Dilithium3PublicKey.hexToBytes(hex);
        return Dilithium3PublicKey.create(encoded);
    }

    @Override
    public CrystalsDilithiumSignature sign(final byte[] secpSignatureEncoded, final PrivateKey privateKeyPQC) {
        return CrystalsDilithiumSignature.create(secpSignatureEncoded, privateKeyPQC);
    }

    @Override
    public boolean verify() {
        return true;
    }
}
