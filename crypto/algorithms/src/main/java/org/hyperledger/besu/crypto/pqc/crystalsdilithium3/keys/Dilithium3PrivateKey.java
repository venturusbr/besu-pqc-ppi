package org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Dilithium3PrivateKey implements java.security.PrivateKey {

    private final byte[] encoded;

    private Dilithium3PrivateKey(final byte[] encoded) {
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    public static Dilithium3PrivateKey create(final byte[] privateKey) {
        checkNotNull(privateKey);
        return new Dilithium3PrivateKey(privateKey);
    }

    public PrivateKey getCrystalsDilithiumPrivateKeyFromEncoded() {
        byte[] encodedByte = getEncoded();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedByte);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String getAlgorithm() {
        return "CrystalsDilithium";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public int hashCode() {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encoded);
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        return intBuffer.get();
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
