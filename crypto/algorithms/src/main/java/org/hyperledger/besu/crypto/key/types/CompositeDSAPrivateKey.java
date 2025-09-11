package org.hyperledger.besu.crypto.key.types;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;

public class CompositeDSAPrivateKey implements PrivateKey{
    private final PrivateKey firstKey;
    private final PrivateKey secondKey;

    public CompositeDSAPrivateKey(final PrivateKey firstKey, final PrivateKey secondKey){
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
        return Bytes.concatenate(
            Bytes.wrap(firstKey.getEncoded()),
            Bytes.wrap(secondKey.getEncoded())
        ).toArrayUnsafe();
    }
}
