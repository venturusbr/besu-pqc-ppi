package org.hyperledger.besu.crypto.key;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.types.CompositeDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositeDSAPublicKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;

public class NodeKeyFactory {
    private NodeKeyFactory(){}

    public static NodeKeyPair createNodeKpFromKeyPair(final KeyPair kp, final DSAParametersSet paramsSet){
        return createNodeKp(Bytes.wrap(kp.getPrivate().getEncoded()),Bytes.wrap(kp.getPublic().getEncoded()), paramsSet);
    }

    public static NodeKeyPair createNodeKp(final Bytes privateKeyBytes, final Bytes publicKeyBytes, final DSAParametersSet paramsSet){
        NodeKeyPair kp;
        switch (paramsSet) {
            case SECP256K1:
            case SECP256R1:
                kp = createNodeSECP256KeyPair(privateKeyBytes, publicKeyBytes, "ECDSA");
                break;
            case MLDSA44:
            case MLDSA65:
            case MLDSA87:
                kp = createNodeMLDSAKeyPair(privateKeyBytes, publicKeyBytes, paramsSet);
                break;
            case SECP256K1MLDSA44:
                // TODO
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }

       return kp;
    }

    public static NodeKeyPair createHybridNodeKp(
        final PrivateKey firstSk,
        final PrivateKey secondSk,
        final PublicKey firstPk,
        final PublicKey secondPk) {
        PrivateKey sk = new CompositeDSAPrivateKey(firstSk, secondSk);
        PublicKey pk = new CompositeDSAPublicKey(firstPk, secondPk);

        return new NodeKeyPair(sk, pk);
    }
    public static NodeKeyPair createNodeSECP256KeyPair(final Bytes privateKey, final Bytes publicKey, final String algorithm){
        SECPPrivateKey secpSk = SECPPrivateKey.create(Bytes32.wrap(privateKey), algorithm);
        SECPPublicKey secpPk = SECPPublicKey.create(publicKey, algorithm);
        return new NodeKeyPair(secpSk, secpPk);
    }

    public static NodeKeyPair createNodeMLDSAKeyPair(final Bytes privateKeyBytes, final Bytes publicKeyBytes, final DSAParametersSet paramsSet){
        PrivateKey sk = MLDSAPrivateKey.create(privateKeyBytes, paramsSet);
        PublicKey pk;
        if(publicKeyBytes == null){
            pk = MLDSAPublicKey.deriveMLDSAPkFromSk(Bytes.wrap(sk.getEncoded()), paramsSet);
            return new NodeKeyPair(sk, pk);
        } 
        pk = MLDSAPublicKey.create(publicKeyBytes, paramsSet);
        return new NodeKeyPair(sk, pk);
    }
}
