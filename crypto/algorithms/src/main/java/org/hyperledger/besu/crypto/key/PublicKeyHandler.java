/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.key;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;

import java.security.PublicKey;
import java.util.Optional;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes32;

public class PublicKeyHandler {
  private PublicKeyHandler() {}

  /**
   * The classical secp256k1 half of a key.
   *
   * <p>The RLPx ECIES handshake and the discv5 handshake are classical regardless of the node's
   * DSA, so they need this key even when the node key is hybrid.
   *
   * @param publicKey a classical or hybrid public key
   * @return the secp256k1 public key
   */
  public static SECPPublicKey secp256k1(final PublicKey publicKey) {
    final PublicKey classicalKey =
        publicKey instanceof CompositePublicKey hybridKey ? hybridKey.getFirstKey() : publicKey;
    if (!(classicalKey instanceof SECPPublicKey secpPublicKey)) {
      throw new IllegalArgumentException(
          "Expected a secp256k1 public key, but found " + classicalKey.getAlgorithm());
    }
    return secpPublicKey;
  }

  /**
   * The public key behind a signature: recovered from the signature wherever the algorithm
   * supports it, and taken from the provided key otherwise.
   *
   * <p>A half whose algorithm supports recovery is always recovered, even when the caller hands in
   * a whole composite key. Verifying a hybrid signature does not check that half, since recovery
   * is what authenticates it, so a stated one would go unchecked and the signature would pass on
   * its other half alone.
   *
   * @param signatureAlgorithm the algorithm that produced the signature
   * @param signature the signature
   * @param maybePartialPk the key that travelled with the payload, if any: the halves that cannot
   *     be recovered, or a whole composite key whose recoverable halves are ignored
   * @param recoveryHash the hash the signature was made over
   * @param object what the signature is over, e.g. {@code tx} or {@code qbft-commit}: each key
   *     actually recovered is recorded under it in the PKR metrics, and a key that is only taken
   *     from {@code maybePartialPk} is not
   * @return the signer's public key
   * @throws IllegalArgumentException if no key can be recovered from the signature, such as one
   *     made on another curve, or if the algorithm cannot recover keys and none was provided:
   *     either way the signature cannot be attributed to anyone
   */
  public static Optional<PublicKey> resolvePublicKey(
      final DigitalSignatureAlgorithm signatureAlgorithm,
      final Signature signature,
      final Optional<PublicKey> maybePartialPk,
      final Bytes32 recoveryHash,
      final String object) {
    if (signatureAlgorithm instanceof HybridDigitalSignatureAlgorithm hybrid) {
      return Optional.of(
          extractHybridPublicKey(hybrid, signature, maybePartialPk, recoveryHash, object));
    }

    return Optional.of(
        resolveSingleAlgorithmPublicKey(
            signatureAlgorithm, signature, maybePartialPk, recoveryHash, object));
  }

  private static PublicKey extractHybridPublicKey(
      final HybridDigitalSignatureAlgorithm hybrid,
      final Signature signature,
      final Optional<PublicKey> maybePartialPk,
      final Bytes32 recoveryHash,
      final String object) {

    final DigitalSignatureAlgorithm first = hybrid.getFirstAlgorithm();
    final DigitalSignatureAlgorithm second = hybrid.getSecondAlgorithm();

    CompositeSignature hybridSignature = (CompositeSignature) signature;
    PublicKey firstPk =
        resolveSingleAlgorithmPublicKey(
            first,
            hybridSignature.getFirstSignature(),
            halfOf(maybePartialPk, CompositePublicKey::getFirstKey),
            recoveryHash,
            object);

    PublicKey secondPk =
        resolveSingleAlgorithmPublicKey(
            second,
            hybridSignature.getSecondSignature(),
            halfOf(maybePartialPk, CompositePublicKey::getSecondKey),
            recoveryHash,
            object);

    return CompositePublicKey.create(firstPk, secondPk);
  }

  /**
   * The half of the provided key that belongs to one algorithm of the hybrid. A partial key is
   * already the half that cannot be recovered, so it is offered to both: the recoverable half
   * ignores it.
   */
  private static Optional<PublicKey> halfOf(
      final Optional<PublicKey> maybePartialPk, final Function<CompositePublicKey, PublicKey> half) {
    return maybePartialPk.map(
        pk -> pk instanceof CompositePublicKey composite ? half.apply(composite) : pk);
  }

  private static PublicKey resolveSingleAlgorithmPublicKey(
      final DigitalSignatureAlgorithm dsa,
      final Signature signature,
      final Optional<PublicKey> maybePartialPk,
      final Bytes32 recoveryHash,
      final String object) {

    if (dsa instanceof PublicKeyRecoverable recoverable) {
      return MetricWriters.timeRecovery(
              object, () -> recoverable.recoverPublicKeyFromSignature(recoveryHash, signature))
          .orElseThrow(() -> new IllegalArgumentException("Cannot recover public key"));
    }

    return maybePartialPk.orElseThrow(
        () ->
            new IllegalArgumentException(
                "Public key must be provided when algorithm does not support PKR"));
  }
}
