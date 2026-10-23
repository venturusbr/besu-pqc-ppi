/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.consensus.common.bft;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;

import java.security.PublicKey;
import java.util.Objects;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A committed seal contributed by a single validator, paired with that validator's public key.
 *
 * <p>The key is present only when the active algorithm cannot recover it from the signature. For a
 * recoverable algorithm such as SECP256K1 the seal alone identifies its signer, because producing a
 * signature that recovers to a given address requires that address's private key -- recovery is
 * itself the proof of authenticity. No such property exists for ML-DSA and other non-recoverable
 * algorithms, so the key must be carried alongside the seal and the seal must be explicitly
 * verified against it. See {@link #recoverVerifiedAuthor}.
 */
public class CommitSeal {

  private static final Logger LOG = LoggerFactory.getLogger(CommitSeal.class);

  /** What a seal is called in the verify metrics when the caller does not name its protocol. */
  public static final String BFT_COMMIT_SEAL = "bft-commit-seal";

  private final Signature signature;
  private final Optional<PublicKey> publicKey;

  /**
   * Instantiates a new commit seal.
   *
   * @param signature the seal itself
   * @param publicKey the signer's public key, required for algorithms without recovery
   */
  public CommitSeal(final Signature signature, final Optional<PublicKey> publicKey) {
    checkNotNull(signature);
    checkNotNull(publicKey);
    this.signature = signature;
    this.publicKey = publicKey;
  }

  /**
   * Instantiates a new commit seal with no public key, which is only sufficient for algorithms that
   * support public key recovery.
   *
   * @param signature the seal itself
   */
  public CommitSeal(final Signature signature) {
    this(signature, Optional.empty());
  }

  /**
   * Gets the seal.
   *
   * @return the signature
   */
  public Signature getSignature() {
    return signature;
  }

  /**
   * Gets the signer's public key, present only for algorithms that cannot recover it from the
   * signature.
   *
   * @return the public key
   */
  public Optional<PublicKey> getPublicKey() {
    return publicKey;
  }

  /**
   * Determines the address of the validator that produced this seal, proving the seal is genuinely
   * theirs.
   *
   * <p>For a recoverable algorithm the address is recovered from the signature, which cannot
   * succeed unless the signer held the corresponding private key. For a non-recoverable algorithm
   * {@link PublicKeyHandler#resolvePublicKey} simply trusts the carried key, so the address it
   * yields would otherwise be unfounded -- anyone can attach a validator's public key, which is
   * public by definition, to a signature they did not produce. The seal is therefore verified
   * against the resolved key before its address is returned.
   *
   * @param dataHash the hash the seal was produced over
   * @return the signer's address, or empty if the seal does not verify
   */
  public Optional<Address> recoverVerifiedAuthor(final Hash dataHash) {
    return recoverVerifiedAuthor(dataHash, BFT_COMMIT_SEAL);
  }

  /**
   * As {@link #recoverVerifiedAuthor(Hash)}, naming the seal in the verify metrics.
   *
   * @param dataHash the hash the seal was produced over
   * @param metricsLabel what the seal is called in the verify metrics, e.g. {@code
   *     qbft-commit-seal}
   * @return the signer's address, or empty if the seal does not verify
   */
  public Optional<Address> recoverVerifiedAuthor(final Hash dataHash, final String metricsLabel) {
    final Bytes32 dataHashBytes = Bytes32.wrap(dataHash.getBytes());
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();

    final PublicKey resolvedPublicKey;
    try {
      resolvedPublicKey =
          PublicKeyHandler.resolvePublicKey(dsa, signature, publicKey, dataHashBytes).get();
    } catch (final RuntimeException e) {
      LOG.info("Discarding commit seal whose public key could not be resolved: {}", e.getMessage());
      return Optional.empty();
    }

    if (!(dsa instanceof PublicKeyRecoverable)
        && !MetricWriters.timeVerification(
            metricsLabel,
            dsa.getDsaParametersSet(),
            () ->
                Boolean.TRUE.equals(
                    DSAProviderFactory.getVerifierProvider()
                        .verifySignature(dataHashBytes, signature, resolvedPublicKey)))) {
      LOG.info("Discarding commit seal that failed verification against its supplied public key.");
      return Optional.empty();
    }

    return Optional.of(Address.extract(resolvedPublicKey));
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final CommitSeal that = (CommitSeal) o;
    return Objects.equals(signature, that.signature) && Objects.equals(publicKey, that.publicKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(signature, publicKey);
  }

  @Override
  public String toString() {
    return "CommitSeal{signature=" + signature + ", publicKey=" + publicKey + '}';
  }
}
