package org.hyperledger.besu.crypto.pqc.sphincsplus;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.hyperledger.besu.crypto.SecureRandomProvider;

import static com.google.common.base.Preconditions.checkNotNull;

public class SphincsPlusSignature {

    private final byte[] encoded;

    private SphincsPlusSignature(final byte[] encoded) {
        this.encoded = encoded;
    }
    
    public static SphincsPlusSignature create(final byte[] dataToSign, final PrivateKey privateKey) {
        checkNotNull(privateKey);
        checkNotNull(dataToSign);
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
            sig.initSign(privateKey, SecureRandomProvider.createSecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            byte[] signature = sig.sign();
            return new SphincsPlusSignature(signature);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
