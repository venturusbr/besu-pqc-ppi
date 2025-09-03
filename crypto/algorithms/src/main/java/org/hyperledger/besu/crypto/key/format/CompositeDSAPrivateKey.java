package org.hyperledger.besu.crypto.key.format;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;

public class CompositeDSAPrivateKey implements PrivateKey{
    private final PrivateKey firstKey;
    private final PrivateKey secondKey;
    private final Bytes encoded;

    public CompositeDSAPrivateKey(final PrivateKey firstKey, final PrivateKey secondKey){
        this.encoded = Bytes.concatenate(
            Bytes.wrap(firstKey.getEncoded()),
            Bytes.wrap(secondKey.getEncoded())
        );
        this.firstKey = firstKey;
        this.secondKey = secondKey;
    }

    public PrivateKey getFirstKey(){
        return firstKey;
    }

    public PrivateKey getSecondKey(){
        return secondKey;
    }

    @Override
    public String getAlgorithm(){
        return firstKey.getAlgorithm() + "-" + secondKey.getAlgorithm();
    }

    @Override
    public String getFormat(){
        return "concatenated";
    }

    @Override
    public byte[] getEncoded(){
        return encoded.toArrayUnsafe();
    }
}
