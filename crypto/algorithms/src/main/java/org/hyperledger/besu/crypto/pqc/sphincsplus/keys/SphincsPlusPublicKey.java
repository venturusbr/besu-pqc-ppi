package org.hyperledger.besu.crypto.pqc.sphincsplus.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;

public class SphincsPlusPublicKey implements java.security.PublicKey {
    
    private final byte[] encoded;

    private SphincsPlusPublicKey(final byte[] encoded) {
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    public static SphincsPlusPublicKey create(final byte[] publicKey) {
        checkNotNull(publicKey);
        return new SphincsPlusPublicKey(publicKey);
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String getAlgorithm() {
      return "SPHINCSPlus";
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
