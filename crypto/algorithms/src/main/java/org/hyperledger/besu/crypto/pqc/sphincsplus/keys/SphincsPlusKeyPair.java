package org.hyperledger.besu.crypto.pqc.sphincsplus.keys;

import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.hyperledger.besu.crypto.SecureRandomProvider;

/** The SphincsPlus Key pair class. */
public class SphincsPlusKeyPair {

    private final SphincsPlusPrivateKey privateKey;
    private final SphincsPlusPublicKey publicKey;

    /**
     * Instantiates a new SphincsPlus Key pair.
     *
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public SphincsPlusKeyPair(final SphincsPlusPrivateKey privateKey, final SphincsPlusPublicKey publicKey) {
        checkNotNull(privateKey);
        checkNotNull(publicKey);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Create SphincsPlus key pair.
     *
     * @param privateKey the private key
     * @param publicKey the public key
     * @return the SphincsPlus key pair
     */
    public static SphincsPlusKeyPair createKeyPair(
        final SphincsPlusPrivateKey privateKey, final SphincsPlusPublicKey publicKey) {
        return new SphincsPlusKeyPair(privateKey, publicKey);
    }

    /**
     * Generate key pair.
     *
     * @param keyPairGenerator the key pair generator
     * @param sphincsPlusParameterSpec the SphincsPlus parameters
     * @return the SphincsPlus key pair
     */
    public static SphincsPlusKeyPair generate(final KeyPairGenerator keyPairGenerator, final SPHINCSPlusParameterSpec sphincsPlusParameterSpec) {
        try {
            keyPairGenerator.initialize(sphincsPlusParameterSpec, SecureRandomProvider.createSecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            byte[] privateKeySphincsPlusByte = privateKey.getEncoded();
            byte[] publicKeySphincsPlusByte = publicKey.getEncoded();

            return new SphincsPlusKeyPair(
                SphincsPlusPrivateKey.create(privateKeySphincsPlusByte),
                SphincsPlusPublicKey.create(publicKeySphincsPlusByte));
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
        
        /**
     * Gets SphincsPlus private key.
     *
     * @return the private key
     */
    public SphincsPlusPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets SphincsPlus public key.
     *
     * @return the public key
     */
    public SphincsPlusPublicKey getPublicKey() {
        return publicKey;
    }
}
