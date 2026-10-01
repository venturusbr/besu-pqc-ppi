package org.hyperledger.besu.crypto.signature;

import static com.google.common.base.Preconditions.checkArgument;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;
import org.hyperledger.besu.crypto.signature.types.FalconSignature;
import org.hyperledger.besu.crypto.signature.types.MLDSASignature;

public class SignatureFactory {
    private SignatureFactory(){}

    private static final SignatureExtractor signatureExtractor = new SignatureExtractor();

    public static Signature createSignatureFromBytes(final Bytes bytes, final DSAParametersSet algo) {

        return switch (algo) {
            case SECP256K1, SECP256R1 ->
                //use V to calculate recId
                SignatureAlgorithmFactory.getInstance().decodeSignature(bytes);
            case MLDSA44, MLDSA65, MLDSA87 ->
                MLDSASignature.create(algo.getName(), bytes);
            case FALCON512 ->
                FalconSignature.create(bytes, algo);
            case SECP256K1FALCON512 -> {
                // SECP256K1's signature is fixed-length and comes first, so Falcon's variable-length
                // signature is simply the remainder. The enclosing RLP item carries the total length.
                final int secpLength = DSAParametersSet.SECP256K1.getSignatureLength();
                checkArgument(
                    bytes.size() > secpLength
                        && bytes.size()
                            <= secpLength + FalconSignature.maxLength(DSAParametersSet.FALCON512),
                    "Invalid signature length for SECP256K1-FALCON512: %s",
                    bytes.size());
                yield CompositeSignature.create(
                    createSignatureFromBytes(bytes.slice(0, secpLength), DSAParametersSet.SECP256K1),
                    FalconSignature.create(bytes.slice(secpLength), DSAParametersSet.FALCON512));
            }
            case SECP256K1MLDSA44 -> {

                int expectedLength =
                DSAParametersSet.SECP256K1MLDSA44.getSignatureLength();

                if (bytes.size() == expectedLength) {

                    Bytes secpSigBytes =
                        signatureExtractor.extractSignatureBytesAtOffset(
                            bytes,
                            0,
                            DSAParametersSet.SECP256K1);

                    Bytes mldsaSigBytes =
                        signatureExtractor.extractSignatureBytesAtOffset(
                            bytes,
                            DSAParametersSet.SECP256K1.getSignatureLength(),
                            DSAParametersSet.MLDSA44);

                    Signature secpSig =
                        createSignatureFromBytes(
                            secpSigBytes,
                            DSAParametersSet.SECP256K1);

                    Signature mldsaSig =
                        createSignatureFromBytes(
                            mldsaSigBytes,
                            DSAParametersSet.MLDSA44);

                    yield CompositeSignature.create(secpSig, mldsaSig);
                }

                throw new IllegalArgumentException( "Invalid signature length for SECP256K1MLDSA44: " + bytes.size());
            }
                
            default ->
                throw new IllegalStateException("Unsupported DSAParametersSet: " + algo);
        };
    }

    public static CompositeSignature createCompositeConcSignature(final Signature first, final Signature second){
        CompositeSignature hybridSignature = CompositeSignature.create(first, second);

        checkArgument(first.encodedBytes().size() + second.encodedBytes().size() == hybridSignature.encodedBytes().size(), "encoded HybridSignature must be the same size as the sum of the first and second signatures");

        return hybridSignature;
    }
}
