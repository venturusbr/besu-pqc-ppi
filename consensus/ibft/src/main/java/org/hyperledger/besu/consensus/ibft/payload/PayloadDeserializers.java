/*
 * Copyright 2020 ConsenSys AG.
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
package org.hyperledger.besu.consensus.ibft.payload;

import org.hyperledger.besu.consensus.common.bft.payload.Payload;
import org.hyperledger.besu.consensus.common.bft.payload.SignedData;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyDecoder;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.security.PublicKey;
import java.util.Optional;

/** The Payload deserializers. */
public class PayloadDeserializers {
  /** Default constructor. */
  protected PayloadDeserializers() {}

  /**
   * Read signed proposal payload from rlp input.
   *
   * @param rlpInput the rlp input
   * @return the signed data
   */
  public static SignedData<ProposalPayload> readSignedProposalPayloadFrom(final RLPInput rlpInput) {

    rlpInput.enterList();
    final ProposalPayload unsignedMessageData = ProposalPayload.readFrom(rlpInput);
    final Signature signature = readSignature(rlpInput);
    final Optional<PublicKey> publicKey = readPublicKey(rlpInput);
    rlpInput.leaveList();

    return from(unsignedMessageData, signature, publicKey);
  }

  /**
   * Read signed prepare payload from rlp input.
   *
   * @param rlpInput the rlp input
   * @return the signed data
   */
  public static SignedData<PreparePayload> readSignedPreparePayloadFrom(final RLPInput rlpInput) {

    rlpInput.enterList();
    final PreparePayload unsignedMessageData = PreparePayload.readFrom(rlpInput);
    final Signature signature = readSignature(rlpInput);
    final Optional<PublicKey> publicKey = readPublicKey(rlpInput);
    rlpInput.leaveList();

    return from(unsignedMessageData, signature, publicKey);
  }

  /**
   * Read signed commit payload from rlp input.
   *
   * @param rlpInput the rlp input
   * @return the signed data
   */
  public static SignedData<CommitPayload> readSignedCommitPayloadFrom(final RLPInput rlpInput) {

    rlpInput.enterList();
    final CommitPayload unsignedMessageData = CommitPayload.readFrom(rlpInput);
    final Signature signature = readSignature(rlpInput);
    final Optional<PublicKey> publicKey = readPublicKey(rlpInput);
    rlpInput.leaveList();

    return from(unsignedMessageData, signature, publicKey);
  }

  /**
   * Read signed round change payload from rlp input.
   *
   * @param rlpInput the rlp input
   * @return the signed data
   */
  public static SignedData<RoundChangePayload> readSignedRoundChangePayloadFrom(
      final RLPInput rlpInput) {

    rlpInput.enterList();
    final RoundChangePayload unsignedMessageData = RoundChangePayload.readFrom(rlpInput);
    final Signature signature = readSignature(rlpInput);
    final Optional<PublicKey> publicKey = readPublicKey(rlpInput);
    rlpInput.leaveList();

    return from(unsignedMessageData, signature, publicKey);
  }

  /**
   * Create signed payload data from unsigned message data.
   *
   * @param <M> the type parameter
   * @param unsignedMessageData the unsigned message data
   * @param signature the signature
   * @param publicKey the signer's public key, present only for algorithms without recovery
   * @return the signed data
   */
  protected static <M extends Payload> SignedData<M> from(
      final M unsignedMessageData,
      final Signature signature,
      final Optional<PublicKey> publicKey) {
    return SignedData.create(unsignedMessageData, signature, publicKey);
  }

  /**
   * Create signed payload data with no supplied public key, which is only sufficient for
   * algorithms that support public key recovery.
   *
   * @param <M> the type parameter
   * @param unsignedMessageData the unsigned message data
   * @param signature the signature
   * @return the signed data
   */
  protected static <M extends Payload> SignedData<M> from(
      final M unsignedMessageData, final Signature signature) {
    return from(unsignedMessageData, signature, Optional.empty());
  }

  /**
   * Read signature from signed message.
   *
   * @param signedMessage the signed message
   * @return the secp signature
   */
  protected static Signature readSignature(final RLPInput signedMessage) {
    final DSAParametersSet dsaParams = DSAProviderFactory.getActiveDsaParametersSet();
    return signedMessage.readBytes(bytes -> SignatureFactory.createSignatureFromBytes(bytes, dsaParams));
  }

  /**
   * Read the signer's public key, which is only present on the wire for algorithms that cannot
   * recover it from the signature.
   *
   * @param signedMessage the signed message
   * @return the public key, or empty for recoverable algorithms
   */
  protected static Optional<PublicKey> readPublicKey(final RLPInput signedMessage) {
    return PublicKeyDecoder.decodeByDsa(DSAProviderFactory.getActiveDSA(), signedMessage);
  }
}
