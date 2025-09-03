package org.hyperledger.besu.crypto.algorithms.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPublicKey;
import org.hyperledger.besu.crypto.signature.CompositeSignature;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SingleSignature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.crypto.signature.CompositeSignature;

public class HybridStrongNestingConcatenation implements HybridDigitalSignatureAlgorithm{

    DigitalSignatureAlgorithm delegateFirstAlgorithm;
    DigitalSignatureAlgorithm delegateSecondAlgorithm;
    DSAParametersSet parametersSet;

    public HybridStrongNestingConcatenation(DigitalSignatureAlgorithm firstAlgorithm, DigitalSignatureAlgorithm secondAlgorithm, DSAParametersSet parametersSet){
        this.delegateFirstAlgorithm = firstAlgorithm;
        this.delegateSecondAlgorithm = secondAlgorithm;
        this.parametersSet = parametersSet;
    }

    @Override
    public Signature sign(Bytes data, PrivateKey sk) {
        CompositeDSAPrivateKey hybridPrivateKey = (CompositeDSAPrivateKey) sk;

        Signature firstSignature = delegateFirstAlgorithm.sign(data, hybridPrivateKey.getFirstKey());
        Signature secondSignature = delegateSecondAlgorithm.sign(Bytes.concatenate(data, firstSignature.encodedBytes()), hybridPrivateKey.getSecondKey());

        return SignatureFactory.createStrongNestedConcSignature(firstSignature, secondSignature);
    }

    // TODO: SignatureExtractor
    @Override
    public Boolean verify(Bytes data, Signature signature, PublicKey pk) {
        CompositeDSAPublicKey hybridPublicKey = (CompositeDSAPublicKey) pk;

        CompositeSignature compositeSignature = (CompositeSignature) signature;

        Signature firstSignature = compositeSignature.getFirstSignature();
        Signature secondSignature = compositeSignature.getSecondSignature();
        // Signature firstSignature = extractSignatureFromBytes(signature.encodedBytes(), 0, delegateFirstAlgorithm.signatureLength());
        // Signature secondSignature = extractSignatureFromBytes(signature.encodedBytes(), delegateFirstAlgorithm.signatureLength(), delegateFirstAlgorithm.signatureLength() + delegateSecondAlgorithm.signatureLength());

        Bytes dataWithFirstSignature = Bytes.wrap(data, firstSignature.getEncodedBytes()); 

        return delegateFirstAlgorithm.verify(data, firstSignature, hybridPublicKey.getFirstKey()) && delegateSecondAlgorithm.verify(dataWithFirstSignature, secondSignature, hybridPublicKey.getSecondKey());
    }

    @Override
    public NodeKeyPair generateKeyPair() {
        //TODO
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
