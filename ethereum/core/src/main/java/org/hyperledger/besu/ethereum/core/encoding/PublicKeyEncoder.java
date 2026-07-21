package org.hyperledger.besu.ethereum.core.encoding;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import static com.google.common.base.Preconditions.checkNotNull;

/*
 * Encodes a public key into RLP based on the DSA type.
 *
 * Encoding rules:
 *
 * - Single DSA:
 *   (pk)  -> encode public key
 *   ()    -> skip (public key is recoverable via PKR)
 *
 * - Hybrid DSA:
 *   (pk1 || pk2) -> encode full composite public key
 *   (pk1)        -> encode only first key (second is recoverable via PKR)
 *   (pk2)        -> encode only second key (first is recoverable via PKR)
 *   ()           -> skip (both keys are recoverable via PKR)
 *
 * Notes:
 * - Public keys are encoded only for algorithms that do NOT support PKR.
 * - Partial Composite public keys (pk1||null or null||pk2) are not created.
 * - When only one key is encoded (hybrid case), the missing key must be
 *   recovered later using PKR during sender construction.
 * - The DSA type (from the transaction) is used to reconstruct hybrid keys.
 */
public class PublicKeyEncoder {
    public static void encodeByDsaId(
        final PublicKey publicKey,
        final Short dsaType,
        final RLPOutput out
    ) {
        checkNotNull(publicKey, "publicKey must not be null");

        final DigitalSignatureAlgorithm dsa =
            DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(dsaType);

        if (publicKey instanceof CompositePublicKey compositePk) {
            if (!(dsa instanceof HybridDigitalSignatureAlgorithm hybridDsa)) {
                throw new IllegalArgumentException("Expected hybrid DSA for composite public key");
            }
            encodeHybridPk(compositePk, hybridDsa, out);
            return;
        }
        if(!pkIsRecovarable(dsa)){
            encodePk(publicKey, out);
        }
    }

    private static void encodeHybridPk(final CompositePublicKey compositePk, final HybridDigitalSignatureAlgorithm hybridDsa, final RLPOutput out){

        Boolean firstPkIsRecoverable = pkIsRecovarable(hybridDsa.getFirstAlgorithm());
        Boolean secondPkIsRecoverable = pkIsRecovarable(hybridDsa.getSecondAlgorithm());

        if(!firstPkIsRecoverable && !secondPkIsRecoverable){
            encodePk(compositePk, out);
            return;
        }

        if(!firstPkIsRecoverable){
            encodePk(compositePk.getFirstKey(), out);
        }
        if(!secondPkIsRecoverable){
            encodePk(compositePk.getSecondKey(), out);
        }
    }

    private static Boolean pkIsRecovarable(final DigitalSignatureAlgorithm dsa){
        return (dsa instanceof PublicKeyRecoverable);
    }

    private static void encodePk(
        final PublicKey pk,
        final RLPOutput out
    ) {
        out.writeBytes(Bytes.wrap(pk.getEncoded()));
    }
}
