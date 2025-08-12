package org.hyperledger.besu.crypto.algorithms.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;
import org.hyperledger.besu.crypto.key.format.HybridDSAPrivateKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.DSASignature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

public class HybridStrongNestingConcatenation implements DigitalSignatureAlgorithm{

    DigitalSignatureAlgorithm delegateFirstAlgorithm;
    DigitalSignatureAlgorithm delegateSecondAlgorithm;

    HybridStrongNestingConcatenation(DigitalSignatureAlgorithm firstAlgorithm, DigitalSignatureAlgorithm secondAlgorithm){
        this.delegateFirstAlgorithm = firstAlgorithm;
        this.delegateSecondAlgorithm = secondAlgorithm;
    }

    @Override
    public String getAlgorithmName() {
        return "HybridStrongNestingConcatenation";
    }

    @Override
    public String getParameterSet() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getParameterSet'");
    }

    @Override
    public Signature sign(Bytes data, PrivateKey sk) {
        HybridDSAPrivateKey hybridPrivateKey = (HybridDSAPrivateKey) sk;

        // PrivateKey secondSk = extractPrivateKeyFromBytes(hybridPrivateKeyBytes, delegateFirstAlgorithm.privateKeyLength(), delegateFirstAlgorithm.privateKeyLength() + delegateSecondAlgorithm.privateKeyLength(), null);

        Signature firstSignature = delegateFirstAlgorithm.sign(data, hybridPrivateKey.getFirstKey());
        Signature secondSignature = delegateSecondAlgorithm.sign(Bytes.concatenate(data, firstSignature.encodedBytes()), hybridPrivateKey.getSecondKey());

        return SignatureFactory.createStrongNestedConcSignature(firstSignature, secondSignature);
    }

    @Override
    public Boolean verify(Bytes data, Signature signature, PublicKey pk) {
        Bytes hybridPublicKeyBytes = Bytes.wrap(pk.getEncoded());

        PublicKey firstPk = extractPublicKeyFromBytes(hybridPublicKeyBytes, 0, delegateFirstAlgorithm.publicKeyLength(), null);

        PublicKey secondPk = extractPublicKeyFromBytes(hybridPublicKeyBytes, delegateFirstAlgorithm.publicKeyLength(), delegateFirstAlgorithm.publicKeyLength() + delegateSecondAlgorithm.publicKeyLength(), null);

        Signature firstSignature = extractSignatureFromBytes(signature.encodedBytes(), 0, delegateFirstAlgorithm.signatureLength());
        Signature secondSignature = extractSignatureFromBytes(signature.encodedBytes(), delegateFirstAlgorithm.signatureLength(), delegateFirstAlgorithm.signatureLength() + delegateSecondAlgorithm.signatureLength());

        Bytes dataWithFirstSignature = Bytes.wrap(data, firstSignature.encodedBytes()); 

        return delegateFirstAlgorithm.verify(data, firstSignature, firstPk) && delegateSecondAlgorithm.verify(dataWithFirstSignature, secondSignature, secondPk);
    }

    @Override
    public NodeKeyPair generateKeyPair() {
        
    }

    @Override
    public Integer signatureLength() {
        return delegateFirstAlgorithm.signatureLength() + delegateSecondAlgorithm.signatureLength();
    }

    @Override
    public Integer privateKeyLength(){
        return delegateFirstAlgorithm.privateKeyLength() + delegateSecondAlgorithm.privateKeyLength();
    }

    @Override
    public Integer publicKeyLength() {
        return delegateFirstAlgorithm.publicKeyLength() + delegateSecondAlgorithm.publicKeyLength();
    }

    @Override
    public Boolean supportsPKR() {
        return false;
    }

    @Override
    public Boolean isHybrid(){
        return true;
    }

    // private PrivateKey extractPrivateKeyFromBytes(Bytes skBytes, Integer fromIndex, Integer toIndex, String format){
    //     Bytes slicedSk = skBytes.slice(fromIndex, toIndex - fromIndex);
    //     return new DSAPrivateKey(getAlgorithmName(), format, slicedSk);
    // }

    // private PublicKey extractPublicKeyFromBytes(Bytes compositePkBytes, Integer fromIndex, Integer toIndex, String format){
    //     Bytes slicedPk = compositePkBytes.slice(fromIndex, toIndex - fromIndex);
    //     return new DSAPublicKey(getAlgorithmName(), format, slicedPk);
    // }

    // private Signature extractSignatureFromBytes(Bytes compositeSignatureBytes, Integer fromIndex, Integer toIndex){
    //     Bytes slicedSignature = compositeSignatureBytes.slice(fromIndex, toIndex - fromIndex);
    //     return new DSASignature(slicedSignature, false);
    // }
}
