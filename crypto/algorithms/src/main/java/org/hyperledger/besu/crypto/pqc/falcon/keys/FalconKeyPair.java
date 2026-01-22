package org.hyperledger.besu.crypto.pqc.falcon.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import org.hyperledger.besu.crypto.SecureRandomProvider;

public class FalconKeyPair {

    private final FalconPrivateKey privateKey;
    private final FalconPublicKey publicKey;

    /**
     * Instantiates a new Falcon Key pair.
     *
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public FalconKeyPair(final FalconPrivateKey privateKey, final FalconPublicKey publicKey) {
        checkNotNull(privateKey);
        checkNotNull(publicKey);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Create Falcon key pair.
     *
     * @param privateKey the private key
     * @param publicKey the public key
     * @return the Falcon key pair
     */
    public static FalconKeyPair createKeyPair(
        final FalconPrivateKey privateKey, final FalconPublicKey publicKey) {
        return new FalconKeyPair(privateKey, publicKey);
    }

    /**
     * Generate Falcon key pair.
     *
     * @param keyPairGenerator the key pair generator
     * @param falconParameterSpec the Falcon parameters
     * @return the Falcon key pair
     */
    public static FalconKeyPair generate(final KeyPairGenerator keyPairGenerator, final FalconParameterSpec falconParameterSpec) {
        try {
            keyPairGenerator.initialize(falconParameterSpec, SecureRandomProvider.createSecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            byte[] privateKeySphincsPlusByte = privateKey.getEncoded();
            byte[] publicKeySphincsPlusByte = publicKey.getEncoded();

            return new FalconKeyPair(
                FalconPrivateKey.create(privateKeySphincsPlusByte),
                FalconPublicKey.create(publicKeySphincsPlusByte));
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
        
        /**
     * Gets Falcon private key.
     *
     * @return the private key
     */
    public FalconPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets Falcon public key.
     *
     * @return the public key
     */
    public FalconPublicKey getPublicKey() {
        return publicKey;
    }
    
}
