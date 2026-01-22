package org.hyperledger.besu.crypto.pqc.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public abstract class PqcPrivateKey implements java.security.PrivateKey {
    private final byte[] encoded;

    protected PqcPrivateKey(final byte[] encoded){
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public abstract String getAlgorithm();
  
    @Override
    public String getFormat() {
      return null;
    }

    public String bytesToHex() {
        StringBuilder result = new StringBuilder();
        for (byte b : encoded) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexToBytes(final String hex) {
        byte[] encoded = new BigInteger(hex, 16).toByteArray();
        return encoded;
    }

    public PrivateKey getPrivateKeyFromEncoded() {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("wip", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
}
