package org.hyperledger.besu.crypto.key;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;

public class PublicKeyHandler {
    private PublicKeyHandler() {}

    public static Optional<PublicKey> resolvePublicKey(
        final DigitalSignatureAlgorithm signatureAlgorithm,
        final Signature signature,
        final Optional<PublicKey> maybePartialPk,
        final Bytes32 recoveryHash) {
        
        if(maybePartialPk.get() instanceof CompositePublicKey) return maybePartialPk;

        if (signatureAlgorithm instanceof HybridDigitalSignatureAlgorithm hybrid) {
            return Optional.of(extractHybridPublicKey(hybrid, signature, maybePartialPk, recoveryHash));
        }

        return Optional.of(resolveSingleAlgorithmPublicKey(
            signatureAlgorithm,
            signature,
            maybePartialPk,
            recoveryHash));
    }

    private static PublicKey extractHybridPublicKey(
        final HybridDigitalSignatureAlgorithm hybrid,
        final Signature signature,
        final Optional<PublicKey> maybePartialPk,
        final Bytes32 recoveryHash) {

        final DigitalSignatureAlgorithm first = hybrid.getFirstAlgorithm();
        final DigitalSignatureAlgorithm second = hybrid.getSecondAlgorithm();

        CompositeSignature hybridSignature = (CompositeSignature) signature;
        PublicKey firstPk =
            resolveSingleAlgorithmPublicKey(
                first,
                hybridSignature.getFirstSignature(),
                maybePartialPk,
                recoveryHash);

        PublicKey secondPk =
            resolveSingleAlgorithmPublicKey(
                second,
                hybridSignature.getSecondSignature(),
                maybePartialPk,
                recoveryHash);

        return CompositePublicKey.create(firstPk, secondPk);
    }

    private static PublicKey resolveSingleAlgorithmPublicKey(
        final DigitalSignatureAlgorithm dsa,
        final Signature signature,
        final Optional<PublicKey> maybePartialPk,
        final Bytes32 recoveryHash) {

        if (dsa instanceof PublicKeyRecoverable recoverable) {
            return recoverable
                .recoverPublicKeyFromSignature(recoveryHash, signature)
                .orElseThrow(
                    () -> new IllegalStateException("Cannot recover public key"));
        }

        if (maybePartialPk == null) {
            throw new IllegalStateException(
                "Public key must be provided when algorithm does not support PKR");
        }

        return maybePartialPk.get();
    }
}
