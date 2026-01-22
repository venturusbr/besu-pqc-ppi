package org.hyperledger.besu.crypto.pqc.sphincsplus.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SphincsPlusPrivateKey implements java.security.PrivateKey {

    private final byte[] encoded;

    private SphincsPlusPrivateKey(final byte[] encoded) {
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    public static SphincsPlusPrivateKey create(final byte[] privateKey) {
        checkNotNull(privateKey);
        return new SphincsPlusPrivateKey(privateKey);
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

    public PrivateKey getSphincsPlusPrivateKeyFromEncoded() {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = null;
      try {
          keyFactory = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
          return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
      } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
          e.printStackTrace();
          return null;
      }
    }
  
}
