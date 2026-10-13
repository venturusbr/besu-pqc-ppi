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

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderTestFixture;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class TestHelpers {

  public static BlockHeader createCliqueSignedBlockHeader(
      final BlockHeaderTestFixture blockHeaderBuilder,
      final KeyPair signer,
      final List<Address> validators) {

    final BlockHeader unsealedHeader =
        blockHeaderBuilder
            .blockHeaderFunctions(new CliqueBlockHeaderFunctions())
            .extraData(CliqueExtraData.encodeUnsealed(Bytes.wrap(new byte[32]), validators))
            .buildHeader();
    final CliqueExtraData unsignedExtraData = CliqueExtraData.decodeRaw(unsealedHeader);

    final Hash signingHash =
        CliqueBlockHashing.calculateDataHashForProposerSeal(unsealedHeader, unsignedExtraData);

    final SECPSignature proposerSignature =
        SignatureAlgorithmFactory.getInstance().sign(Bytes32.wrap(signingHash.getBytes()), signer);

    final Bytes signedExtraData =
        new CliqueExtraData(
                unsignedExtraData.getVanityData(),
                proposerSignature,
                unsignedExtraData.getValidators(),
                unsealedHeader)
            .encode();

    blockHeaderBuilder.extraData(signedExtraData);

    return blockHeaderBuilder.buildHeader();
  }

  /**
   * Seals a header with the active algorithm the way {@code CliqueBlockCreator} does, carrying the
   * public key of {@code keyOwner} when the algorithm cannot recover it. Passing a different {@code
   * signer} produces a seal that does not match the key it carries.
   */
  public static BlockHeader createSealedBlockHeader(
      final BlockHeaderTestFixture blockHeaderBuilder,
      final List<Address> validators,
      final KeyPair keyOwner,
      final KeyPair signer) {
    final Bytes vanity = Bytes.wrap(new byte[CliqueExtraData.EXTRA_VANITY_LENGTH]);
    final BlockHeader unsealedHeader =
        blockHeaderBuilder
            .blockHeaderFunctions(new CliqueBlockHeaderFunctions())
            .extraData(CliqueExtraData.encodeUnsealed(vanity, validators))
            .buildHeader();
    final Optional<PublicKey> carriedKey =
        CliqueExtraData.proposerKeyToCarry(keyOwner.getPublicKey());

    final Hash signingHash =
        CliqueBlockHashing.calculateDataHashForProposerSeal(
            unsealedHeader,
            new CliqueExtraData(vanity, null, validators, carriedKey, unsealedHeader));
    final Signature seal =
        DSAProviderFactory.getActiveDSA()
            .sign(Bytes.wrap(signingHash.getBytes()), signer.getPrivateKey());

    return blockHeaderBuilder
        .extraData(
            new CliqueExtraData(vanity, seal, validators, carriedKey, unsealedHeader).encode())
        .buildHeader();
  }
}
