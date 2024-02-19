package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class CrystalsDilithiumSignature {

    private final byte[] encoded;

    private CrystalsDilithiumSignature(final byte[] encoded) {
        this.encoded = encoded;
    }

    public static CrystalsDilithiumSignature create(final byte[] dataToSign, final PrivateKey privateKey) {
        checkNotNull(privateKey);
        checkNotNull(dataToSign);
        try {
            Signature sig = Signature.getInstance("Dilithium");
            sig.initSign(privateKey, SecureRandom.getInstanceStrong());
            sig.update(dataToSign, 0, dataToSign.length);
            byte[] signature = sig.sign();
            return new CrystalsDilithiumSignature(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
