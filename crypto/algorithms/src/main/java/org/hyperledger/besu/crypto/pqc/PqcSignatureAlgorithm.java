package org.hyperledger.besu.crypto.pqc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.hyperledger.besu.crypto.pqc.PqcProvider;

public abstract class PqcSignatureAlgorithm {

    public abstract String getAlgorithmName();

    public PqcSignatureAlgorithm(){
        PqcProvider.initializeBouncyCastle();
    }

    public boolean verify(PublicKey publicKey, byte[] dataToSign, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(getAlgorithmName(), "BCPQC");
            sig.initVerify(publicKey);
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }
}
