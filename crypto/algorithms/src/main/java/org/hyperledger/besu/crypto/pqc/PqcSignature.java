package org.hyperledger.besu.crypto.pqc;

import static com.google.common.base.Preconditions.checkNotNull;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class PqcSignature {

    private static final Logger LOG = LoggerFactory.getLogger(PqcSignature.class);

    private byte[] encoded;

    private void setSignature(final byte[] signature){
        this.encoded = signature;
    };
    
    protected abstract String getSignatureName();
    
    public void create(final byte[] dataToSign, final PrivateKey privateKey) {
        checkNotNull(privateKey);
        checkNotNull(dataToSign);
        try {
            Signature sig = Signature.getInstance(getSignatureName(), "BCPQC");
            sig.initSign(privateKey, SecureRandomProvider.createSecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            byte[] signature = sig.sign();
            setSignature(signature);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            LOG.info(e.getMessage());
        }
    }

    public byte[] getEncoded() {
        return encoded;
    }
}