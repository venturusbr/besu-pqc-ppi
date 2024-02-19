package org.hyperledger.besu.crypto.pqc.falcon;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.hyperledger.besu.crypto.SecureRandomProvider;

public class FalconSignature {

    private final byte[] encoded;

    private FalconSignature(final byte[] encoded) {
        this.encoded = encoded;
    }
    
    public static FalconSignature create(final byte[] dataToSign, final PrivateKey privateKey) {
        checkNotNull(privateKey);
        checkNotNull(dataToSign);
        try {
            Signature sig = Signature.getInstance("Falcon", "BCPQC");
            sig.initSign(privateKey, SecureRandomProvider.createSecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            byte[] signature = sig.sign();
            return new FalconSignature(signature);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getEncoded() {
        return encoded;
    }
    
}
