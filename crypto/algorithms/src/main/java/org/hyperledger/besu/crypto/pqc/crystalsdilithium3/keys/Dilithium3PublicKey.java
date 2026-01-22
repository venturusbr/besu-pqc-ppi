package org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Dilithium3PublicKey implements java.security.PublicKey {
    private final byte[] encoded;

    private Dilithium3PublicKey(final byte[] encoded) {
        checkNotNull(encoded);
        this.encoded = encoded;
    }

    public static Dilithium3PublicKey create(final byte[] publicKey) {
        checkNotNull(publicKey);
        return new Dilithium3PublicKey(publicKey);
    }

    public PublicKey getCrystalsDilithiumPublicKeyFromEncoded() {
        byte[] encodedByte = getEncoded();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedByte);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
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
