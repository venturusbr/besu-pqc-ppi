package org.hyperledger.besu.crypto.key;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;

public class NodeKeyFactory {
    private final KeyExtractor keyExtractor;

    public NodeKeyFactory(final KeyExtractor keyExtractor){
        this.keyExtractor = keyExtractor;
    }

    public PrivateKey createPrivateKey(final Bytes privateKeyBytes, final DSAParametersSet paramsSet, final PrivateKeyRepresentation firstSkRep, final PrivateKeyRepresentation secondSkRep){
        PrivateKey sk;
        switch (paramsSet) {
            case SECP256K1:
            case SECP256R1:
                sk = SECPPrivateKey.create(Bytes32.wrap(privateKeyBytes), paramsSet.getName());
                break;
            case MLDSA44:
            case MLDSA65:
            case MLDSA87:
                sk = MLDSAPrivateKey.create(privateKeyBytes, paramsSet);
                break;
            case SECP256K1MLDSA44:
                Bytes secpSkBytes = keyExtractor.extractPrivateKeyBytesAtOffset(privateKeyBytes, 0, DSAParametersSet.SECP256K1, firstSkRep);
                PrivateKey secpSk = createPrivateKey(secpSkBytes, DSAParametersSet.SECP256K1, PrivateKeyRepresentation.EXPANDED, null);

                Bytes mldsaSk44Bytes = keyExtractor.extractPrivateKeyBytesAtOffset(privateKeyBytes, DSAParametersSet.SECP256K1.getPrivateKeyLength() + 1, DSAParametersSet.MLDSA44, secondSkRep);
                PrivateKey mldsaSk44 = createPrivateKey(mldsaSk44Bytes, DSAParametersSet.MLDSA44, PrivateKeyRepresentation.EXPANDED, null);

                sk = CompositePrivateKey.create(secpSk, mldsaSk44);
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return sk;
    }

    public PublicKey createPublicKey(final PrivateKey privateKey, final DSAParametersSet paramsSet){
        PublicKey pk;
        switch (paramsSet) {
            case SECP256K1:
            case SECP256R1:
                SECPPrivateKey secpSk = (SECPPrivateKey) privateKey;
                BigInteger keyInteger = secpSk.getD();
                pk = SECPPublicKey.create(keyInteger, paramsSet.getName());
                break;
            case MLDSA44:
            case MLDSA65:
            case MLDSA87:
                pk = MLDSAPublicKey.create(privateKey, paramsSet);
                break;
            case SECP256K1MLDSA44:
                CompositePrivateKey compositeSk = (CompositePrivateKey) privateKey;

                PrivateKey secpFirstSk = compositeSk.getFirstKey();
                PrivateKey mldsaSecondSk = compositeSk.getSecondKey();

                PublicKey secpFirstPk = createPublicKey(secpFirstSk, DSAParametersSet.SECP256K1);
                PublicKey mldsaSecondPk = createPublicKey(mldsaSecondSk, DSAParametersSet.MLDSA44);

                pk = CompositePublicKey.create(secpFirstPk, mldsaSecondPk);
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return pk;
    }

    public PublicKey createPublicKey(final Bytes publicKeyBytes, final DSAParametersSet paramsSet){
        PublicKey pk;
        switch (paramsSet) {
            case SECP256K1:
            case SECP256R1:
                pk = SECPPublicKey.create(publicKeyBytes, paramsSet.getName());
                break;
            case MLDSA44:
            case MLDSA65:
            case MLDSA87:
                pk = MLDSAPublicKey.create(publicKeyBytes, paramsSet);
                break;
            case SECP256K1MLDSA44:
                Bytes secpPkBytes = keyExtractor.extractPublicKeyBytesAtOffset(publicKeyBytes, 0, DSAParametersSet.SECP256K1);
                PublicKey secpPk = createPublicKey(secpPkBytes, DSAParametersSet.SECP256K1);

                Bytes mldsaPk44Bytes = keyExtractor.extractPublicKeyBytesAtOffset(publicKeyBytes, DSAParametersSet.SECP256K1.getPublicKeyLength() + 1, DSAParametersSet.MLDSA44);
                PublicKey mldsaPk44 = createPublicKey(mldsaPk44Bytes, DSAParametersSet.MLDSA44);

                pk = CompositePublicKey.create(secpPk, mldsaPk44);
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return pk;
    }

    public NodeKeyPair createNodeKpFromKeyPair(final KeyPair kp){
        return createNodeKp(kp.getPrivate(),kp.getPublic());
    }

    public NodeKeyPair createNodeKp(final PrivateKey privateKey, final PublicKey publicKey){
        return new NodeKeyPair(privateKey, publicKey);
    }
}
