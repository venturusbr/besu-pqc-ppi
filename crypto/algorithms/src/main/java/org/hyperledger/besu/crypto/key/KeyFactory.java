package org.hyperledger.besu.crypto.key;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PrivateKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PublicKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;

public class KeyFactory {
    private static final KeyExtractor keyExtractor = new KeyExtractor();

    private KeyFactory(){}

    public static PrivateKey createPrivateKey(final Bytes privateKeyBytes, final DSAParametersSet paramsSet, final PrivateKeyRepresentation firstSkRep, final PrivateKeyRepresentation secondSkRep){
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
            case FALCON512:
                sk = Falcon512PrivateKey.create(privateKeyBytes);
                break;
            case SECP256K1MLDSA44:
                Bytes secpSkBytes = keyExtractor.extractPrivateKeyBytesAtOffset(privateKeyBytes, 0, DSAParametersSet.SECP256K1, firstSkRep);
                PrivateKey secpSk = createPrivateKey(secpSkBytes, DSAParametersSet.SECP256K1, PrivateKeyRepresentation.EXPANDED, null);

                Bytes mldsaSk44Bytes = keyExtractor.extractPrivateKeyBytesAtOffset(privateKeyBytes, DSAParametersSet.SECP256K1.getPrivateKeyLength() + 1, DSAParametersSet.MLDSA44, secondSkRep);
                PrivateKey mldsaSk44 = createPrivateKey(mldsaSk44Bytes, DSAParametersSet.MLDSA44, PrivateKeyRepresentation.EXPANDED, null);

                sk = CompositePrivateKey.create(secpSk, mldsaSk44);
                break;
            case SECP256K1FALCON512: {
                // Both halves are fixed-length: SECP256K1 || Falcon-512 (f || g || F || h).
                final int secpSkLength = DSAParametersSet.SECP256K1.getPrivateKeyLength();
                if (privateKeyBytes.size() != secpSkLength + Falcon512PrivateKey.LENGTH) {
                    throw new IllegalArgumentException(
                        "SECP256K1-FALCON512 private key must be "
                            + (secpSkLength + Falcon512PrivateKey.LENGTH)
                            + " bytes, got "
                            + privateKeyBytes.size());
                }
                sk =
                    CompositePrivateKey.create(
                        createPrivateKey(
                            privateKeyBytes.slice(0, secpSkLength),
                            DSAParametersSet.SECP256K1,
                            PrivateKeyRepresentation.EXPANDED,
                            null),
                        Falcon512PrivateKey.create(privateKeyBytes.slice(secpSkLength)));
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return sk;
    }

    public static PublicKey createPublicKey(final PrivateKey privateKey, final DSAParametersSet paramsSet){
        PublicKey pk;
        switch (paramsSet) {
            case SECP256K1:
            case SECP256R1:
                SECPPrivateKey secpSk = (SECPPrivateKey) privateKey;
                pk = SignatureAlgorithmFactory.getInstance().createPublicKey(secpSk);
                break;
            case MLDSA44:
            case MLDSA65:
            case MLDSA87:
                pk = MLDSAPublicKey.create(privateKey, paramsSet);
                break;
            case FALCON512:
                pk = Falcon512PublicKey.create(privateKey);
                break;
            case SECP256K1MLDSA44:
                CompositePrivateKey compositeSk = (CompositePrivateKey) privateKey;

                PrivateKey secpFirstSk = compositeSk.getFirstKey();
                PrivateKey mldsaSecondSk = compositeSk.getSecondKey();

                PublicKey secpFirstPk = createPublicKey(secpFirstSk, DSAParametersSet.SECP256K1);
                PublicKey mldsaSecondPk = createPublicKey(mldsaSecondSk, DSAParametersSet.MLDSA44);

                pk = CompositePublicKey.create(secpFirstPk, mldsaSecondPk);
                break;
            case SECP256K1FALCON512: {
                final CompositePrivateKey hybridSk = (CompositePrivateKey) privateKey;
                pk =
                    CompositePublicKey.create(
                        createPublicKey(hybridSk.getFirstKey(), DSAParametersSet.SECP256K1),
                        createPublicKey(hybridSk.getSecondKey(), DSAParametersSet.FALCON512));
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return pk;
    }

    public static Optional<PublicKey> createPublicKey(final Bytes publicKeyBytes, final DSAParametersSet paramsSet){
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
            case FALCON512:
                pk = Falcon512PublicKey.create(publicKeyBytes);
                break;
            case SECP256K1MLDSA44:
                int expectedFullLength =
                    DSAParametersSet.SECP256K1MLDSA44.getPublicKeyLength();

                if (publicKeyBytes.size() == expectedFullLength) {

                    Bytes secpPkBytes =
                        keyExtractor.extractPublicKeyBytesAtOffset(
                            publicKeyBytes, 0, DSAParametersSet.SECP256K1);

                    Bytes mldsaPkBytes =
                        keyExtractor.extractPublicKeyBytesAtOffset(
                            publicKeyBytes,
                            DSAParametersSet.SECP256K1.getPublicKeyLength() + 1,
                            DSAParametersSet.MLDSA44);

                    Optional<PublicKey> secpPk =
                        createPublicKey(secpPkBytes, DSAParametersSet.SECP256K1);

                    Optional<PublicKey> mldsaPk =
                        createPublicKey(mldsaPkBytes, DSAParametersSet.MLDSA44);

                    return Optional.of(CompositePublicKey.create(secpPk.get(), mldsaPk.get()));
                }
                if(publicKeyBytes.size() == DSAParametersSet.MLDSA44.getPublicKeyLength()){
                    return Optional.of(MLDSAPublicKey.create(publicKeyBytes, DSAParametersSet.MLDSA44));
                }
                throw new IllegalArgumentException("Wrong public key size for: " + paramsSet.getName());
            case SECP256K1FALCON512: {
                final int secpPkLength = DSAParametersSet.SECP256K1.getPublicKeyLength();
                if (publicKeyBytes.size() == secpPkLength + Falcon512PublicKey.LENGTH) {
                    return Optional.of(
                        CompositePublicKey.create(
                            SECPPublicKey.create(
                                publicKeyBytes.slice(0, secpPkLength),
                                DSAParametersSet.SECP256K1.getName()),
                            Falcon512PublicKey.create(publicKeyBytes.slice(secpPkLength))));
                }
                // Transactions carry only the Falcon half: SECP256K1's is recovered from its signature.
                if (publicKeyBytes.size() == Falcon512PublicKey.LENGTH) {
                    return Optional.of(Falcon512PublicKey.create(publicKeyBytes));
                }
                throw new IllegalArgumentException(
                    "Wrong public key size for " + paramsSet.getName() + ": " + publicKeyBytes.size());
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return Optional.ofNullable(pk);
    }

    public static PublicKey createCompositePublicKey(final PublicKey firstPk, final PublicKey secondPk){
        return CompositePublicKey.create(firstPk, secondPk);
    }

    public static KeyPair createKeyPair(final PrivateKey privateKey, final PublicKey publicKey){
        return new KeyPair(privateKey, publicKey);
    }

    public static KeyPair createKeyPair(
            final Bytes privateKeyBytes,
            final Bytes publicKeyBytes,
            final DSAParametersSet dsaParams) {
        PrivateKey sk = createPrivateKey(privateKeyBytes, dsaParams, PrivateKeyRepresentation.EXPANDED, PrivateKeyRepresentation.EXPANDED);

        PublicKey pk = createPublicKey(sk, dsaParams);

        return createKeyPair(sk, pk);
    }

    public static KeyPair createHybridKeyPair(final KeyPair firstKp, final KeyPair secondKp){
        PrivateKey hybridSk = CompositePrivateKey.create(firstKp.getPrivateKey(), secondKp.getPrivateKey());
        PublicKey hybridPk = CompositePublicKey.create(firstKp.getPublicKey(), secondKp.getPublicKey());

        return createKeyPair(hybridSk, hybridPk);
    }
}
