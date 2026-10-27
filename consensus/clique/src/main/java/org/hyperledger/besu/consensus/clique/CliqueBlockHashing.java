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
package org.hyperledger.besu.consensus.clique;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;

import java.security.PublicKey;
import java.util.Optional;
import java.util.function.Supplier;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** The Clique block hashing. */
public class CliqueBlockHashing {

  /** What the proposer seal is called in the sign, verify and PKR metrics. */
  private static final String CLIQUE_BLOCK_HEADER = "clique-block-header";
  /** Default constructor. */
  private CliqueBlockHashing() {}

  /**
   * Constructs a hash of the block header, suitable for use when creating the proposer seal. The
   * extra data is modified to have a null proposer seal and empty list of committed seals.
   *
   * @param header The header for which a proposer seal is to be calculated
   * @param cliqueExtraData The extra data block which is to be inserted to the header once seal is
   *     calculated
   * @return the hash of the header suitable for signing as the proposer seal
   */
  public static Hash calculateDataHashForProposerSeal(
      final BlockHeader header, final CliqueExtraData cliqueExtraData) {
    final Bytes headerRlp = serializeHeaderWithoutProposerSeal(header, cliqueExtraData);
    return Hash.hash(headerRlp); // Proposer hash is the hash of the RLP
  }

  /**
   * Recovers the proposer's {@link Address} from the proposer seal.
   *
   * <p>For an algorithm with public key recovery the address is recovered from the seal, which
   * cannot succeed unless the proposer held the matching private key. Otherwise the header carries
   * the proposer's public key, and since anyone can attach a validator's public key to a seal they
   * did not produce, the seal is verified against that key before its address is trusted.
   *
   * @param header the block header that was signed by the proposer seal
   * @param cliqueExtraData the parsed CliqueExtraData from the header
   * @return the proposer address
   * @throws IllegalArgumentException if the seal does not verify against the key the header carries
   */
  public static Address recoverProposerAddress(
      final BlockHeader header, final CliqueExtraData cliqueExtraData) {
    if (!cliqueExtraData.getProposerSeal().isPresent()) {
      if (header.getNumber() == BlockHeader.GENESIS_BLOCK_NUMBER) {
        return Address.ZERO;
      }
      throw new IllegalArgumentException(
          "Supplied cliqueExtraData does not include a proposer " + "seal");
    }
    final Hash proposerHash = calculateDataHashForProposerSeal(header, cliqueExtraData);
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    if (!CliqueExtraData.carriesProposerKey(dsa)) {
      return Address.signatureToAddress(
          dsa,
          cliqueExtraData.getProposerSeal().get(),
          Optional.empty(),
          proposerHash,
          CLIQUE_BLOCK_HEADER);
    }
    return recoverVerifiedProposerAddress(dsa, cliqueExtraData, proposerHash);
  }

  private static Address recoverVerifiedProposerAddress(
      final DigitalSignatureAlgorithm dsa,
      final CliqueExtraData cliqueExtraData,
      final Hash proposerHash) {
    final Signature seal = cliqueExtraData.getProposerSeal().get();
    final Bytes32 proposerHashBytes = Bytes32.wrap(proposerHash.getBytes());

    final PublicKey proposerPublicKey;
    try {
      proposerPublicKey =
          PublicKeyHandler.resolvePublicKey(
                  dsa,
                  seal,
                  cliqueExtraData.getProposerPublicKey(),
                  proposerHashBytes,
                  CLIQUE_BLOCK_HEADER)
              .get();
    } catch (final RuntimeException e) {
      throw new IllegalArgumentException(
          "Could not resolve the proposer's public key: " + e.getMessage(), e);
    }

    if (!MetricWriters.timeVerification(
        CLIQUE_BLOCK_HEADER,
        dsa.getDsaParametersSet(),
        () ->
            Boolean.TRUE.equals(
                DSAProviderFactory.getVerifierProvider()
                    .verifySignature(proposerHashBytes, seal, proposerPublicKey)))) {
      throw new IllegalArgumentException(
          "Proposer seal does not verify against the public key the header carries");
    }
    return Address.extract(proposerPublicKey);
  }

  private static Bytes serializeHeaderWithoutProposerSeal(
      final BlockHeader header, final CliqueExtraData cliqueExtraData) {
    return serializeHeader(header, cliqueExtraData::encodeWithoutProposerSeal);
  }

  private static Bytes serializeHeader(
      final BlockHeader header, final Supplier<Bytes> extraDataSerializer) {
    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    out.startList();

    out.writeBytes(header.getParentHash().getBytes());
    out.writeBytes(header.getOmmersHash().getBytes());
    out.writeBytes(header.getCoinbase().getBytes());
    out.writeBytes(header.getStateRoot().getBytes());
    out.writeBytes(header.getTransactionsRoot().getBytes());
    out.writeBytes(header.getReceiptsRoot().getBytes());
    out.writeBytes(header.getLogsBloom().getBytes());
    out.writeBytes(header.getDifficulty().toMinimalBytes());
    out.writeLongScalar(header.getNumber());
    out.writeLongScalar(header.getGasLimit());
    out.writeLongScalar(header.getGasUsed());
    out.writeLongScalar(header.getTimestamp());
    out.writeBytes(extraDataSerializer.get());
    out.writeBytes(header.getMixHash().getBytes());
    out.writeLong(header.getNonce());
    header.getBaseFee().ifPresent(out::writeUInt256Scalar);
    out.endList();
    return out.encoded();
  }
}
