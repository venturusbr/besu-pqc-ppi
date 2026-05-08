package org.hyperledger.besu.ethereum.core.encoding;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.key.KeyFactory;
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
 *   (pk1 || pk2) -> decode full composite public key
 *   (pk1)        -> decode only first key (second is recoverable via PKR)
 *   (pk2)        -> decode only second key (first is recoverable via PKR)
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
    
    final DigitalSignatureAlgorithm dsa =
        SignatureAlgorithmFactory.getSupportedDsaById(dsaType);

    if (!(dsa instanceof HybridDigitalSignatureAlgorithm)) {
      if (isRecoverable(dsa)) {
        return Optional.empty();
      }

      final Bytes pkBytes = in.readBytes();
      return KeyFactory.createPublicKey(pkBytes, dsa.getDsaParametersSet());
    }

    final HybridDigitalSignatureAlgorithm hybrid =
        (HybridDigitalSignatureAlgorithm) dsa;

    final DigitalSignatureAlgorithm firstAlgo = hybrid.getFirstAlgorithm();
    final DigitalSignatureAlgorithm secondAlgo = hybrid.getSecondAlgorithm();

    final boolean firstRec = isRecoverable(firstAlgo);
    final boolean secondRec = isRecoverable(secondAlgo);

    if (firstRec && secondRec) {
      return Optional.empty();
    }

    if (!firstRec && !secondRec) {
      final Bytes compositePkBytes = in.readBytes();

      return KeyFactory.createPublicKey(compositePkBytes, dsa.getDsaParametersSet());
    }

    if (!firstRec || !secondRec) {
      Bytes partialPkBytes = in.readBytes();

      return KeyFactory.createPublicKey(partialPkBytes, dsa.getDsaParametersSet());
    }

    throw new IllegalStateException("Unreachable state");
  }

  private static boolean isRecoverable(final DigitalSignatureAlgorithm dsa) {
    return dsa instanceof PublicKeyRecoverable;
  }
}