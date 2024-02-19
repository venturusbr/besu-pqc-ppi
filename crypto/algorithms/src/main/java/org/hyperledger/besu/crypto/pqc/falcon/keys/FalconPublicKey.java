package org.hyperledger.besu.crypto.pqc.falcon.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

public class FalconPublicKey implements java.security.PublicKey{
    
    private final byte[] encoded;

    private FalconPublicKey(final byte[] encoded) {
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    public static FalconPublicKey create(final byte[] publicKey) {
        checkNotNull(publicKey);
        return new FalconPublicKey(publicKey);
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String getAlgorithm() {
      return "Falcon";
    }
  
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

}
