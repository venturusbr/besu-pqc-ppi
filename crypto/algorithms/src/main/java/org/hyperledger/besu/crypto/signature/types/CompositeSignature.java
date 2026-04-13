package org.hyperledger.besu.crypto.signature.types;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.SignatureValidationContext;
import org.hyperledger.besu.crypto.signature.Signature;

public class CompositeSignature implements Signature{
    private final Signature firstSignature;
    private final Signature secondSignature;

    private CompositeSignature(final Signature firstSignature, final Signature secondSignature){
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
    public Boolean isValid(SignatureValidationContext context){
        return firstSignature.isValid(context) && secondSignature.isValid(context);
    }

    @Override
    public Bytes encodedBytes() {
        return Bytes.concatenate(
            Bytes.wrap(firstSignature.encodedBytes()),
            Bytes.wrap(secondSignature.encodedBytes())
        );
    }

    public static CompositeSignature create(final Signature firstSignature, final Signature secondSignature){
        return new CompositeSignature(firstSignature, secondSignature);
    }
    
}
