package org.hyperledger.besu.ethereum.core.encoding;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

/*
 * Decodes a public key from RLP based on the DSA type.
 *
 * Encoding rules:
 *
 * - Single DSA:
 *   (pk)  -> decode public key
 *   ()    -> skip (public key is recoverable via PKR)
 *
 * - Hybrid DSA:
 *   (pk1 || pk2) -> decode full composite public key (neither half is recoverable)
 *   (pk1)        -> decode only first key (second is recoverable via PKR); a full composite key is rejected
 *   (pk2)        -> decode only second key (first is recoverable via PKR); a full composite key is rejected
 *   ()           -> skip (both keys are recoverable via PKR)
 *
 * Notes:
 * - Public keys are encoded only for algorithms that do NOT support PKR.
 * - Partial Composite public keys (pk1||null or null||pk2) are not supported.
 * - When only one key is encoded (hybrid case), the missing key must be
 *   recovered later using PKR during sender construction.
 * - The DSA type (from the transaction) is used to reconstruct hybrid keys.
 */
public class PublicKeyDecoder {

  public static Optional<PublicKey> decodeByDsaId(
      final Short dsaType,
      final RLPInput in) {

    return decodeByDsa(
        DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(dsaType), in);
  }

  /*
   * Same decoding rules as decodeByDsaId, but for callers that already hold the algorithm
   * rather than an account-enabled DSA id (e.g. consensus messages, which use the node's
   * active DSA).
   */
  public static Optional<PublicKey> decodeByDsa(
      final DigitalSignatureAlgorithm dsa,
      final RLPInput in) {

    if (!carriesPublicKey(dsa)) {
      return Optional.empty();
    }
    return fromProvidedBytes(dsa, in.readBytes());
  }

  /*
   * Builds the public key a payload carries from its raw bytes, under the same rules as
   * decodeByDsa. For callers that receive the key outside RLP, such as a code delegation
   * deserialized from JSON.
   *
   * Throws IllegalArgumentException when the bytes are not the key the algorithm expects.
   */
  public static Optional<PublicKey> fromProvidedBytes(
      final DigitalSignatureAlgorithm dsa,
      final Bytes pkBytes) {

    if (!carriesPublicKey(dsa)) {
      // Every key is recovered from the signature, so none is accepted from the payload.
      throw new IllegalArgumentException(
          dsa.getDsaParametersSet().getName()
              + " keys are recovered from the signature, so no public key may be provided");
    }

    if (!(dsa instanceof HybridDigitalSignatureAlgorithm hybrid)) {
      return KeyFactory.createPublicKey(pkBytes, dsa.getDsaParametersSet());
    }

    final DigitalSignatureAlgorithm firstAlgo = hybrid.getFirstAlgorithm();
    final DigitalSignatureAlgorithm secondAlgo = hybrid.getSecondAlgorithm();

    final boolean firstRec = isRecoverable(firstAlgo);
    final boolean secondRec = isRecoverable(secondAlgo);

    if (!firstRec && !secondRec) {
      return KeyFactory.createPublicKey(pkBytes, dsa.getDsaParametersSet());
    }

    // Only the half that cannot be recovered travels with the payload, so it is decoded with
    // that half's own parameters. Decoding with the hybrid's would also accept the full
    // composite key, letting a sender state the recoverable half instead of having it recovered
    // from the signature.
    final DigitalSignatureAlgorithm providedAlgo = firstRec ? secondAlgo : firstAlgo;
    final DSAParametersSet providedParams = providedAlgo.getDsaParametersSet();
    if (pkBytes.size() != providedParams.getPublicKeyLength()) {
      throw new IllegalArgumentException(
          "Expected a "
              + providedParams.getName()
              + " public key of "
              + providedParams.getPublicKeyLength()
              + " bytes, got "
              + pkBytes.size());
    }

    return KeyFactory.createPublicKey(pkBytes, providedParams);
  }

  /*
   * Whether a payload signed with this algorithm carries a public key at all: it does unless
   * every key involved can be recovered from the signature.
   */
  private static boolean carriesPublicKey(final DigitalSignatureAlgorithm dsa) {
    if (dsa instanceof HybridDigitalSignatureAlgorithm hybrid) {
      return !(isRecoverable(hybrid.getFirstAlgorithm())
          && isRecoverable(hybrid.getSecondAlgorithm()));
    }
    return !isRecoverable(dsa);
  }

  private static boolean isRecoverable(final DigitalSignatureAlgorithm dsa) {
    return dsa instanceof PublicKeyRecoverable;
  }
}
