package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;

public class CompositeSignature implements Signature{
    private final Signature firstSignature;
    private final Signature secondSignature;

    public CompositeSignature(final Signature firstSignature, final Signature secondSignature){
        this.firstSignature = firstSignature;
        this.secondSignature = secondSignature;
    }

    public Signature getFirstSignature(){
        return firstSignature;
    }

    public Signature getSecondSignature(){
        return secondSignature;
    }

    @Override
    public String getAlgorithm(){
        return firstSignature.getAlgorithm() + "-" + secondSignature.getAlgorithm();
    }

    @Override
    public Bytes encodedBytes() {
        return Bytes.concatenate(
            Bytes.wrap(firstSignature.encodedBytes()),
            Bytes.wrap(secondSignature.encodedBytes())
        );
    }
    
}
