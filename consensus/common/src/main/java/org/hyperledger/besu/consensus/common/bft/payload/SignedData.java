/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.consensus.common.bft.payload;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.SignatureValidationContext;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyEncoder;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import java.security.PublicKey;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * The type Signed data.
 *
 * @param <M> the type parameter of Payload
 */
public class SignedData<M extends Payload> implements Authored {

  private static final SignatureValidationContext DISALLOW_MALLEABILITY =
      new SignatureValidationContext(true);

  private final Address sender;
  private final Signature signature;
  private final M unsignedPayload;
  private final Optional<PublicKey> publicKey;

  /**
   * Create signed data from a message received from the network, verifying the signature.
   *
   * <p>When the active algorithm supports public key recovery, recovering a key that hashes to the
   * claimed author is itself the proof of authenticity, so no separate verification is performed.
   * When it does not, {@link PublicKeyHandler#resolvePublicKey} takes the halves that cannot be
   * recovered from {@code maybePublicKey}, so the signature is explicitly verified against the
   * resolved key here. This is the single point at which an inbound message signature is checked --
   * the derived author is cached, so every later {@link #getAuthor()} call is free.
   *
   * @param <T> the type parameter
   * @param payload the payload
   * @param signature the signature
   * @param maybePublicKey the signer's public key, required for algorithms without recovery
   * @return the signed data
   * @throws IllegalArgumentException if the signature is malleable or fails verification
   */
  public static <T extends Payload> SignedData<T> create(
      final T payload, final Signature signature, final Optional<PublicKey> maybePublicKey) {
    final Hash msgHash = payload.hashForSignature();
    final Bytes32 msgHashBytes = Bytes32.wrap(msgHash.getBytes());
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();

    final PublicKey resolvedPublicKey =
        PublicKeyHandler.resolvePublicKey(dsa, signature, maybePublicKey, msgHashBytes).get();

    if (!(dsa instanceof PublicKeyRecoverable)
        && !MetricWriters.timeVerification(
            payload.getMetricsLabel(),
            dsa.getDsaParametersSet(),
            () ->
                Boolean.TRUE.equals(
                    DSAProviderFactory.getVerifierProvider()
                        .verifySignature(msgHashBytes, signature, resolvedPublicKey)))) {
      throw new IllegalArgumentException("Signature verification failed");
    }

    return new SignedData<>(payload, Address.extract(resolvedPublicKey), signature, maybePublicKey);
  }

  /**
   * Create signed data. Equivalent to {@link #create(Payload, Signature, Optional)} with no
   * supplied public key, which is only sufficient for algorithms that support public key recovery.
   *
   * @param <T> the type parameter
   * @param payload the payload
   * @param signature the signature
   * @return the signed data
   * @throws IllegalArgumentException if the signature is invalid
   */
  public static <T extends Payload> SignedData<T> create(
      final T payload, final Signature signature) {
    return create(payload, signature, Optional.empty());
  }

  /**
   * Create signed data for a message this node has just signed itself. The signature is not
   * verified, since we produced it (doing so would repeat work already known to succeed).
   *
   * @param <T> the type parameter
   * @param payload the payload
   * @param signature the signature produced by this node
   * @param maybePublicKey this node's public key, required for algorithms without recovery
   * @return the signed data
   * @throws IllegalArgumentException if the signature is malleable
   */
  public static <T extends Payload> SignedData<T> createLocallySigned(
      final T payload, final Signature signature, final Optional<PublicKey> maybePublicKey) {
    final Hash msgHash = payload.hashForSignature();
    // The key, when given, is this node's own, so the sender is derived from it directly.
    // Resolving it would recover its recoverable half from the signature just to get the same
    // key back.
    final Address sender =
        maybePublicKey
            .map(Address::extract)
            .orElseGet(
                () ->
                    Address.signatureToAddress(
                        DSAProviderFactory.getActiveDSA(), signature, maybePublicKey, msgHash));
    return new SignedData<>(payload, sender, signature, maybePublicKey);
  }

  private SignedData(
      final M unsignedPayload,
      final Address sender,
      final Signature signature,
      final Optional<PublicKey> publicKey) {
    if (!signature.isValid(DISALLOW_MALLEABILITY)) {
      throw new IllegalArgumentException("Signature is invalid");
    }
    this.unsignedPayload = unsignedPayload;
    this.sender = sender;
    this.signature = signature;
    this.publicKey = publicKey;
  }

  @Override
  public Address getAuthor() {
    return sender;
  }

  /**
   * Gets payload.
   *
   * @return the payload
   */
  public M getPayload() {
    return unsignedPayload;
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
   * Write to. The public key is appended only when the active algorithm cannot recover it from the
   * signature, so the encoding is unchanged for recoverable algorithms such as SECP256K1.
   *
   * @param output the output
   */
  public void writeTo(final RLPOutput output) {
    output.startList();
    unsignedPayload.writeTo(output);
    output.writeBytes(signature.encodedBytes());
    publicKey.ifPresent(
        pk -> PublicKeyEncoder.encodeByDsa(pk, DSAProviderFactory.getActiveDSA(), output));
    output.endList();
  }

  /**
   * Encode.
   *
   * @return the bytes
   */
  public Bytes encode() {
    final BytesValueRLPOutput rlpEncode = new BytesValueRLPOutput();
    writeTo(rlpEncode);
    return rlpEncode.encoded();
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final SignedData<?> that = (SignedData<?>) o;
    return Objects.equals(sender, that.sender)
        && Objects.equals(signature, that.signature)
        && Objects.equals(unsignedPayload, that.unsignedPayload);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sender, signature, unsignedPayload);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", SignedData.class.getSimpleName() + "[", "]")
        .add("sender=" + sender)
        .add("signature=" + signature)
        .add("unsignedPayload=" + unsignedPayload)
        .toString();
  }
}
