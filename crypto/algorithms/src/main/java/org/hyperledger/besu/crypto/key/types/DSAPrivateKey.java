package org.hyperledger.besu.crypto.key.types;

import org.apache.tuweni.bytes.Bytes;

public class DSAPrivateKey implements java.security.PrivateKey{
    private final String algorithmName;
    private final String format;
    private final Bytes encoded;

    public DSAPrivateKey(final String algorithmName, final String format, final Bytes encoded){
        this.algorithmName = algorithmName;
        this.format = format;
        this.encoded = encoded;
    }

    @Override
    public String getAlgorithm() {
        return algorithmName;
    }
    @Override
    public String getFormat() {
        return format;
    }
    @Override
    public byte[] getEncoded() {
        return encoded.toArrayUnsafe();
    }
}
