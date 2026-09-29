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
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;

import java.security.PublicKey;
import java.util.Optional;

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

  public static Optional<PublicKey> resolvePublicKey(
      final DigitalSignatureAlgorithm signatureAlgorithm,
      final Signature signature,
      final Optional<PublicKey> maybePartialPk,
      final Bytes32 recoveryHash) {
    if (maybePartialPk.isPresent()) {
      if (maybePartialPk.get() instanceof CompositePublicKey) return maybePartialPk;

      if (signatureAlgorithm instanceof HybridDigitalSignatureAlgorithm hybrid) {
        return Optional.of(extractHybridPublicKey(hybrid, signature, maybePartialPk, recoveryHash));
      }
    }

    return Optional.of(
        resolveSingleAlgorithmPublicKey(
            signatureAlgorithm, signature, maybePartialPk, recoveryHash));
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
            first, hybridSignature.getFirstSignature(), maybePartialPk, recoveryHash);

    PublicKey secondPk =
        resolveSingleAlgorithmPublicKey(
            second, hybridSignature.getSecondSignature(), maybePartialPk, recoveryHash);

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
          .orElseThrow(() -> new IllegalStateException("Cannot recover public key"));
    }

    return maybePartialPk.orElseThrow(
        () ->
            new IllegalStateException(
                "Public key must be provided when algorithm does not support PKR"));
  }
}
