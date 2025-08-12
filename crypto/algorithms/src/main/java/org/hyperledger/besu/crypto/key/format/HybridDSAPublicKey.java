package org.hyperledger.besu.crypto.key.format;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

public class HybridDSAPublicKey implements PublicKey{
    private final PublicKey firstKey;
    private final PublicKey secondKey;
    private final Bytes encoded;

    public HybridDSAPublicKey(final PublicKey firstKey, final PublicKey secondKey){
        this.encoded = Bytes.concatenate(
            Bytes.wrap(firstKey.getEncoded()),
            Bytes.wrap(secondKey.getEncoded())
        );
        this.firstKey = firstKey;
        this.secondKey = secondKey;
    }

    public PublicKey getFirstKey(){
        return firstKey;
    }

    public PublicKey getSecondKey(){
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
