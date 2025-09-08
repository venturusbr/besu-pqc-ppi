package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;

public class CompositeSignature implements Signature{
    private final SingleSignature firstSignature;
    private final SingleSignature secondSignature;
    private final Bytes encoded;

    public CompositeSignature(final SingleSignature firstSignature, final SingleSignature secondSignature){
        this.encoded = Bytes.concatenate(
            Bytes.wrap(firstSignature.encodedBytes()),
            Bytes.wrap(secondSignature.encodedBytes())
        );
        this.firstSignature = firstSignature;
        this.secondSignature = secondSignature;
    }

    public SingleSignature getFirstSignature(){
        return firstSignature;
    }

    public SingleSignature getSecondSignature(){
        return secondSignature;
    }

    @Override
    public String getAlgorithm(){
        return firstSignature.getAlgorithm() + "-" + secondSignature.getAlgorithm();
    }

    @Override
    public Bytes encodedBytes() {
        return encoded;
    }
    
}
