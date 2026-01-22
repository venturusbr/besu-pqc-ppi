package org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class Dilithium3KeyPair {
    private final Dilithium3PrivateKey privateKey;
    private final Dilithium3PublicKey publicKey;

    private Dilithium3KeyPair(final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey) {
        checkNotNull(privateKey);
        checkNotNull(publicKey);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public static Dilithium3KeyPair generateCrystalsDilithiumPair(final KeyPairGenerator keyPairGenerator,
            final DilithiumParameterSpec parameterSpec) {
        try {
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            byte[] privateKeyBytes = privateKey.getEncoded();
            byte[] publicKeyBytes = publicKey.getEncoded();

            return new Dilithium3KeyPair(
                    Dilithium3PrivateKey.create(privateKeyBytes),
                    Dilithium3PublicKey.create(publicKeyBytes));
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Dilithium3KeyPair createKeyPair(final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey){
        return new Dilithium3KeyPair(privateKey, publicKey);
    }

    public Dilithium3PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public Dilithium3PublicKey getPublicKey() {
        return this.publicKey;
    }
}
