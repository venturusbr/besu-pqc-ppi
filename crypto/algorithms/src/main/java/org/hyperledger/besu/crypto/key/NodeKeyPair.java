package org.hyperledger.besu.crypto.key;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;
import org.hyperledger.besu.crypto.key.format.HybridDSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.HybridDSAPublicKey;

public class NodeKeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private NodeKeyPair(final PrivateKey sk, final PublicKey pk){
        checkNotNull(sk);
        checkNotNull(pk);
        this.privateKey = sk;
        this.publicKey = pk;
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public PublicKey getPublicKey(){
        return publicKey;
    }

    public static NodeKeyPair create(Bytes privateKeyBytes, Bytes publicKeyBytes, String algorithmName){
       PrivateKey sk = new DSAPrivateKey(algorithmName, "single", privateKeyBytes);

       PublicKey pk = new DSAPublicKey(algorithmName, "single", publicKeyBytes);

       return new NodeKeyPair(sk, pk);
    }

    public static NodeKeyPair createHybrid(
        Bytes privateKeyBytes,
        Bytes publicKeyBytes,
        String firstAlgorithmName,
        String secondAlgorithmName,
        KeyExtractor keyExtractor,
        int firstSkLength,
        int secondSkLength,
        int firstPkLength,
        int secondPkLength) {

        PrivateKey firstSk = keyExtractor.extractPrivateKeyAtOffset(privateKeyBytes, 0, firstSkLength, firstAlgorithmName, "single");
        PrivateKey secondSk = keyExtractor.extractPrivateKeyAtOffset(privateKeyBytes, firstSkLength, secondSkLength, firstAlgorithmName, "single");

        PublicKey firstPk = keyExtractor.extractPublicKeyAtOffset(publicKeyBytes, 0, firstPkLength, secondAlgorithmName, "single");
        PublicKey secondPk = keyExtractor.extractPublicKeyAtOffset(publicKeyBytes, firstPkLength, secondPkLength, secondAlgorithmName, "single");

        PrivateKey sk = new HybridDSAPrivateKey(firstSk, secondSk);
        PublicKey pk = new HybridDSAPublicKey(firstPk, secondPk);

        return new NodeKeyPair(sk, pk);
    }

    // private static PrivateKey extractPrivateKeyAtOffset(Bytes skBytes, Integer fromIndex, Integer toIndex, String format){
    //     Bytes slicedSk = skBytes.slice(fromIndex, toIndex - fromIndex);
    //     return new DSAPrivateKey(getAlgorithmName(), format, slicedSk);
    // }

    // private static PublicKey extractPublicKeyAtOffset(){

    // }
}
