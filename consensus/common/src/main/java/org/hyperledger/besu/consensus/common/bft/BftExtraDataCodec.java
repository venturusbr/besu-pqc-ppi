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
package org.hyperledger.besu.consensus.common.bft;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyDecoder;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyEncoder;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The Bft extra data codec. */
public abstract class BftExtraDataCodec {

  /** The enum Encoding type. */
  protected enum EncodingType {
    /** All encoding type. */
    ALL,
    /** Exclude commit seals encoding type. */
    EXCLUDE_COMMIT_SEALS,
    /** Exclude commit seals and round number encoding type. */
    EXCLUDE_COMMIT_SEALS_AND_ROUND_NUMBER
  }

  private static final Logger LOG = LoggerFactory.getLogger(BftExtraDataCodec.class);

  /** The constant EXTRA_VANITY_LENGTH. */
  public static int EXTRA_VANITY_LENGTH = 32;

  /** Default constructor. */
  public BftExtraDataCodec() {}

  /**
   * Encode.
   *
   * @param bftExtraData the bft extra data
   * @return the bytes
   */
  public Bytes encode(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.ALL);
  }

  /**
   * Encode without commit seals.
   *
   * @param bftExtraData the bft extra data
   * @return the bytes
   */
  public Bytes encodeWithoutCommitSeals(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.EXCLUDE_COMMIT_SEALS);
  }

  /**
   * Encode without commit seals and round number.
   *
   * @param bftExtraData the bft extra data
   * @return the bytes
   */
  public Bytes encodeWithoutCommitSealsAndRoundNumber(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.EXCLUDE_COMMIT_SEALS_AND_ROUND_NUMBER);
  }

  /**
   * Encode.
   *
   * @param bftExtraData the bft extra data
   * @param encodingType the encoding type
   * @return the bytes
   */
  protected abstract Bytes encode(final BftExtraData bftExtraData, final EncodingType encodingType);

  /**
   * Decode.
   *
   * @param blockHeader the block header
   * @return the bft extra data
   */
  public BftExtraData decode(final BlockHeader blockHeader) {
    final Object inputExtraData = blockHeader.getParsedExtraData();
    if (inputExtraData instanceof BftExtraData) {
      return (BftExtraData) inputExtraData;
    }
    LOG.warn(
        "Expected a BftExtraData instance but got {}. Reparsing required.",
        inputExtraData != null ? inputExtraData.getClass().getName() : "null");
    return decodeRaw(blockHeader.getExtraData());
  }

  /**
   * Writes the commit seal list. Each seal is followed by the signer's public key, but only when
   * the active algorithm cannot recover that key from the signature -- {@link PublicKeyEncoder}
   * emits nothing for a recoverable algorithm, so the encoding is unchanged for SECP256K1.
   *
   * @param seals the seals to encode
   * @param output the rlp output
   */
  protected static void encodeCommitSeals(
      final Collection<CommitSeal> seals, final RLPOutput output) {
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    output.startList();
    for (final CommitSeal seal : seals) {
      output.writeBytes(seal.getSignature().encodedBytes());
      if (!(dsa instanceof PublicKeyRecoverable)) {
        // Decoding reads a key for every seal under such an algorithm, so writing one only when
        // it happens to be present would shift every subsequent item.
        PublicKeyEncoder.encodeByDsa(
            seal.getPublicKey()
                .orElseThrow(
                    () ->
                        new IllegalStateException(
                            "Commit seal carries no public key and "
                                + dsa.getDsaParametersSet().getName()
                                + " cannot recover one from the signature")),
            dsa,
            output);
      }
    }
    output.endList();
  }

  /**
   * Reads the commit seal list written by {@link #encodeCommitSeals}. The seal and its key are
   * adjacent items rather than a nested list, so that a seal written for a recoverable algorithm is
   * a bare byte string exactly as before this field carried keys.
   *
   * @param rlpInput the rlp input
   * @return the decoded seals
   */
  protected static List<CommitSeal> decodeCommitSeals(final RLPInput rlpInput) {
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    final DSAParametersSet dsaParams = DSAProviderFactory.getActiveDsaParametersSet();

    final List<CommitSeal> seals = new ArrayList<>();
    rlpInput.enterList();
    while (!rlpInput.isEndOfCurrentList()) {
      final Signature signature =
          SignatureFactory.createSignatureFromBytes(rlpInput.readBytes(), dsaParams);
      seals.add(new CommitSeal(signature, PublicKeyDecoder.decodeByDsa(dsa, rlpInput)));
    }
    rlpInput.leaveList();
    return seals;
  }

  /**
   * Decode raw.
   *
   * @param bytes the bytes
   * @return the bft extra data
   */
  public abstract BftExtraData decodeRaw(Bytes bytes);
}
