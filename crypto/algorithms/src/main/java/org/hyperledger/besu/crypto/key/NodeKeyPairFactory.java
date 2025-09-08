package org.hyperledger.besu.crypto.key;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPublicKey;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;

public class NodeKeyPairFactory {
    private NodeKeyPairFactory(){}

    public static NodeKeyPair createFromKeyPair(KeyPair kp, String algorithmName){
        return create(Bytes.wrap(kp.getPrivate().getEncoded()),Bytes.wrap(kp.getPublic().getEncoded()), algorithmName);
    }

    public static NodeKeyPair create(Bytes privateKeyBytes, Bytes publicKeyBytes, String algorithmName){
       PrivateKey sk = new DSAPrivateKey(algorithmName, "RAW", privateKeyBytes);

       PublicKey pk = new DSAPublicKey(algorithmName, "RAW", publicKeyBytes);

       return new NodeKeyPair(sk, pk);
    }

    public static NodeKeyPair createHybrid(
        PrivateKey firstSk,
        PrivateKey secondSk,
        PublicKey firstPk,
        PublicKey secondPk) {
        PrivateKey sk = new CompositeDSAPrivateKey(firstSk, secondSk);
        PublicKey pk = new CompositeDSAPublicKey(firstPk, secondPk);

        return new NodeKeyPair(sk, pk);
    }
}
