package org.hyperledger.besu.crypto.algorithms.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

public class HybridStrongNestingConcatenation implements HybridDigitalSignatureAlgorithm{

    DigitalSignatureAlgorithm delegateFirstAlgorithm;
    DigitalSignatureAlgorithm delegateSecondAlgorithm;
    DSAParametersSet parametersSet;

    public HybridStrongNestingConcatenation(final DigitalSignatureAlgorithm firstAlgorithm, final DigitalSignatureAlgorithm secondAlgorithm, final DSAParametersSet parametersSet){
        this.delegateFirstAlgorithm = firstAlgorithm;
        this.delegateSecondAlgorithm = secondAlgorithm;
        this.parametersSet = parametersSet;
    }

    @Override
    public Signature sign(final Bytes data, final PrivateKey sk) {
        CompositePrivateKey hybridPrivateKey = (CompositePrivateKey) sk;

        Signature firstSignature = delegateFirstAlgorithm.sign(data, hybridPrivateKey.getFirstKey());
        Signature secondSignature = delegateSecondAlgorithm.sign(Bytes.concatenate(data, firstSignature.encodedBytes()), hybridPrivateKey.getSecondKey());

        return SignatureFactory.createCompositeConcSignature(firstSignature, secondSignature);
    }

    @Override
    public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
        CompositePublicKey hybridPublicKey = (CompositePublicKey) pk;

        CompositeSignature compositeSignature = (CompositeSignature) signature;

        Signature firstSignature = compositeSignature.getFirstSignature();
        Signature secondSignature = compositeSignature.getSecondSignature();

        Bytes dataWithFirstSignature = Bytes.concatenate(data, firstSignature.encodedBytes()); 

        CompletableFuture<Boolean> firstVerify = CompletableFuture.supplyAsync(() ->
            delegateFirstAlgorithm.verify(data, firstSignature, hybridPublicKey.getFirstKey())
        );

        CompletableFuture<Boolean> secondVerify = CompletableFuture.supplyAsync(() ->
            delegateSecondAlgorithm.verify(dataWithFirstSignature, secondSignature, hybridPublicKey.getSecondKey())
        );

        return firstVerify.join() && secondVerify.join();
    }

    @Override
    public NodeKeyPair generateNodeKeyPair(final KeyManager keyManager) {
        // TODO
        // NodeKeyPair firstKeyPair = delegateFirstAlgorithm.generateKeyPair();
        // NodeKeyPair secondKeyPair = delegateSecondAlgorithm.generateKeyPair();


        return null;
    }

    @Override
    public DSAParametersSet getDsaParametersSet() {
        return parametersSet;
    }

    @Override
    public DigitalSignatureAlgorithm getFirstAlgorithm(){
        return delegateFirstAlgorithm;
    }

    @Override 
    public DigitalSignatureAlgorithm getSecondAlgorithm(){
        return delegateSecondAlgorithm;
    }
}
