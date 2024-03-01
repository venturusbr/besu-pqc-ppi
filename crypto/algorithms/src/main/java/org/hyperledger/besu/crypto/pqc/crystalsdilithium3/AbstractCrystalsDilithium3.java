package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;

public abstract class AbstractCrystalsDilithium3 extends PqcSignatureAlgorithm {

    private final DilithiumParameterSpec[] DILITHIUM_PARAMETER_SPEC = {
            DilithiumParameterSpec.dilithium2,
            DilithiumParameterSpec.dilithium3,
            DilithiumParameterSpec.dilithium5
    };

    protected KeyPairGenerator keyPairGenerator;

    public Dilithium3KeyPair generateKeyPair() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("Dilithium");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        Dilithium3KeyPair keyPair = Dilithium3KeyPair.generateCrystalsDilithiumPair(keyPairGenerator, DILITHIUM_PARAMETER_SPEC[SignatureAlgorithmFactory.getPqcParameterSpecIndex()]);

        return keyPair;
    }

    public Dilithium3KeyPair createDilithium3KeyPair(final Dilithium3PrivateKey privateKey,
            final Dilithium3PublicKey publicKey) {
        return Dilithium3KeyPair.createKeyPair(privateKey, publicKey);
    }

    public Dilithium3PrivateKey createPrivateKey(final String hex) {
        byte[] encoded = Dilithium3PrivateKey.hexToBytes(hex);
        return Dilithium3PrivateKey.create(encoded);
    }

    public Dilithium3PublicKey createPublicKey(final String hex) {
        byte[] encoded = Dilithium3PublicKey.hexToBytes(hex);
        return Dilithium3PublicKey.create(encoded);
    }
}
