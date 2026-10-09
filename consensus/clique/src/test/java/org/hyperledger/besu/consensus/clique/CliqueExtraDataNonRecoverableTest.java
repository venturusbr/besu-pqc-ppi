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
package org.hyperledger.besu.consensus.clique;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderTestFixture;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Clique headers sealed with algorithms that cannot recover a public key from a signature. Such a
 * header carries the proposer's key, and the seal must be verified against it: a seal alone no
 * longer identifies the proposer, and anyone can attach a validator's public key to a seal they did
 * not produce.
 */
class CliqueExtraDataNonRecoverableTest {

  private static final Bytes VANITY = Bytes.wrap(new byte[CliqueExtraData.EXTRA_VANITY_LENGTH]);
  private static final int FOOTER_LENGTH = 4;

  private DigitalSignatureAlgorithm dsa;

  private void useAlgorithm(final DSAParametersSet params)
      throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.setNodeActiveDSA(params.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    dsa = DSAProviderFactory.getActiveDSA();
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealedHeaderIsAttributedToItsProposer(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final KeyPair other = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer), addressOf(other));

    final BlockHeader header = seal(fixture(1), validators, proposer, proposer);
    final CliqueExtraData decoded = CliqueExtraData.decodeRaw(header);

    assertThat(decoded.getValidators()).isEqualTo(validators);
    assertThat(decoded.getProposerSeal()).isPresent();
    assertThat(decoded.getProposerAddress()).isEqualTo(addressOf(proposer));
    assertThat(decoded.encode()).isEqualTo(header.getExtraData());
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void headerCarriesOnlyTheKeyThatCannotBeRecovered(final DSAParametersSet params)
      throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));

    final BlockHeader header = seal(fixture(1), validators, proposer, proposer);
    final CliqueExtraData decoded = CliqueExtraData.decodeRaw(header);

    final Bytes carriedKey = Bytes.wrap(decoded.getProposerPublicKey().orElseThrow().getEncoded());
    assertThat(carriedKey).isEqualTo(Bytes.wrap(nonRecoverablePart(proposer).getEncoded()));
    final int sealLength = decoded.getProposerSeal().orElseThrow().encodedBytes().size();
    assertThat(header.getExtraData().size())
        .isEqualTo(
            CliqueExtraData.EXTRA_VANITY_LENGTH
                + Address.SIZE * validators.size()
                + carriedKey.size()
                + sealLength
                + FOOTER_LENGTH);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealMadeWithAnotherKeyIsRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair victim = dsa.generateNodeKeyPair();
    final KeyPair attacker = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(victim));

    // The attacker seals the block but attaches the victim's public key.
    final BlockHeader forged = seal(fixture(1), validators, victim, attacker);

    assertThatThrownBy(() -> CliqueExtraData.decodeRaw(forged).getProposerAddress())
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void keySwappedAfterSealingIsRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final KeyPair other = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer), addressOf(other));
    final BlockHeaderTestFixture builder = fixture(1);
    final BlockHeader header = seal(builder, validators, proposer, proposer);

    final Bytes extraData = header.getExtraData();
    final Bytes proposerKey = Bytes.wrap(nonRecoverablePart(proposer).getEncoded());
    final Bytes otherKey = Bytes.wrap(nonRecoverablePart(other).getEncoded());
    final int keyStart = CliqueExtraData.EXTRA_VANITY_LENGTH + Address.SIZE * validators.size();
    assertThat(extraData.slice(keyStart, proposerKey.size())).isEqualTo(proposerKey);
    final BlockHeader swapped =
        builder
            .extraData(
                Bytes.concatenate(
                    extraData.slice(0, keyStart),
                    otherKey,
                    extraData.slice(keyStart + proposerKey.size())))
            .buildHeader();

    assertThatThrownBy(() -> CliqueExtraData.decodeRaw(swapped).getProposerAddress())
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealDoesNotCoverAModifiedHeader(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));
    final BlockHeaderTestFixture builder = fixture(1);
    final BlockHeader header = seal(builder, validators, proposer, proposer);

    final BlockHeader modified = builder.gasLimit(header.getGasLimit() + 1).buildHeader();

    assertThatThrownBy(() -> CliqueExtraData.decodeRaw(modified).getProposerAddress())
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealedHeaderWithoutAKeyIsRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));
    final BlockHeaderTestFixture builder = fixture(1);
    final BlockHeader header = seal(builder, validators, proposer, proposer);
    final CliqueExtraData sealed = CliqueExtraData.decodeRaw(header);

    final Bytes withoutKey =
        new CliqueExtraData(VANITY, sealed.getProposerSeal().orElseThrow(), validators, header)
            .encode();

    assertThatThrownBy(() -> CliqueExtraData.decodeRaw(builder.extraData(withoutKey).buildHeader()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("carries none");
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void keyOfTheWrongLengthIsRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));
    final BlockHeaderTestFixture builder = fixture(1);
    final Bytes extraData = seal(builder, validators, proposer, proposer).getExtraData();

    final int keyLength = nonRecoverablePart(proposer).getEncoded().length;
    final int sealLength = extraData.size() - FOOTER_LENGTH - keyLength - 32 - Address.SIZE;
    final int keyStart = CliqueExtraData.EXTRA_VANITY_LENGTH + Address.SIZE;
    // Drop the key's last byte and state the shorter length.
    final Bytes truncatedKey =
        Bytes.concatenate(
            extraData.slice(0, keyStart + keyLength - 1),
            extraData.slice(keyStart + keyLength, sealLength),
            Bytes.ofUnsignedShort(keyLength - 1),
            Bytes.ofUnsignedShort(sealLength));

    assertThatThrownBy(
            () -> CliqueExtraData.decodeRaw(builder.extraData(truncatedKey).buildHeader()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void truncatedSealIsRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));
    final BlockHeaderTestFixture builder = fixture(1);
    final Bytes extraData = seal(builder, validators, proposer, proposer).getExtraData();

    final int keyLength = nonRecoverablePart(proposer).getEncoded().length;
    final int sealLength = extraData.size() - FOOTER_LENGTH - keyLength - 32 - Address.SIZE;
    final int sealStart = CliqueExtraData.EXTRA_VANITY_LENGTH + Address.SIZE + keyLength;
    final Bytes truncatedSeal =
        Bytes.concatenate(
            extraData.slice(0, sealStart + sealLength - 1),
            Bytes.ofUnsignedShort(keyLength),
            Bytes.ofUnsignedShort(sealLength - 1));
    final BlockHeader header = builder.extraData(truncatedSeal).buildHeader();

    // A fixed-length seal fails to parse; a variable-length Falcon seal parses but cannot verify.
    assertThatThrownBy(() -> CliqueExtraData.decodeRaw(header).getProposerAddress())
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void malformedLayoutsAreRejected(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final List<Address> validators = List.of(addressOf(proposer));
    final BlockHeaderTestFixture builder = fixture(1);
    final Bytes extraData = seal(builder, validators, proposer, proposer).getExtraData();
    final Bytes body = extraData.slice(0, extraData.size() - FOOTER_LENGTH);
    final Bytes footer = extraData.slice(extraData.size() - FOOTER_LENGTH);

    final Bytes tooShort = Bytes.wrap(new byte[CliqueExtraData.EXTRA_VANITY_LENGTH + 3]);
    final Bytes lengthsBeyondTheData =
        Bytes.concatenate(body, Bytes.ofUnsignedShort(0xFFFF), footer.slice(2));
    final Bytes leftoverByte =
        Bytes.concatenate(
            extraData.slice(0, CliqueExtraData.EXTRA_VANITY_LENGTH),
            Bytes.of(0),
            extraData.slice(CliqueExtraData.EXTRA_VANITY_LENGTH));

    for (final Bytes malformed : List.of(tooShort, lengthsBeyondTheData, leftoverByte)) {
      assertThatThrownBy(
              () -> CliqueExtraData.decodeRaw(builder.extraData(malformed).buildHeader()))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void unsealedExtraDataUsesTheKeyCarryingLayout(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final List<Address> validators =
        List.of(Address.fromHexString("0x01"), Address.fromHexString("0x02"));

    assertThat(CliqueExtraData.encodeUnsealed(VANITY, validators))
        .isEqualTo(
            Bytes.concatenate(
                VANITY,
                validators.get(0).getBytes(),
                validators.get(1).getBytes(),
                Bytes.fromHexString("0x00000000")));
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void genesisIsAcceptedInEitherLayout(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final List<Address> validators =
        List.of(Address.fromHexString("0x01"), Address.fromHexString("0x02"));
    final Bytes vanityAndValidators =
        Bytes.concatenate(VANITY, validators.get(0).getBytes(), validators.get(1).getBytes());

    final Bytes keyCarryingLayout =
        Bytes.concatenate(vanityAndValidators, Bytes.fromHexString("0x00000000"));
    final Bytes recoverableLayout =
        Bytes.concatenate(vanityAndValidators, Bytes.wrap(new byte[65]));

    for (final Bytes extraData : List.of(keyCarryingLayout, recoverableLayout)) {
      final BlockHeader genesis = fixture(0).extraData(extraData).buildHeader();
      final CliqueExtraData decoded = CliqueExtraData.decodeRaw(genesis);
      assertThat(decoded.getValidators()).isEqualTo(validators);
      assertThat(decoded.getProposerSeal()).isEmpty();
      assertThat(decoded.getProposerAddress()).isEqualTo(Address.ZERO);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void recoverableLayoutIsOnlyAcceptedForGenesis(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final Bytes recoverableLayout =
        Bytes.concatenate(
            VANITY, Address.fromHexString("0x01").getBytes(), Bytes.wrap(new byte[65]));

    assertThatThrownBy(
            () -> CliqueExtraData.decodeRaw(fixture(1).extraData(recoverableLayout).buildHeader()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static BlockHeader seal(
      final BlockHeaderTestFixture builder,
      final List<Address> validators,
      final KeyPair keyOwner,
      final KeyPair signer) {
    return TestHelpers.createSealedBlockHeader(builder, validators, keyOwner, signer);
  }

  private PublicKey nonRecoverablePart(final KeyPair keyPair) {
    return dsa instanceof HybridDigitalSignatureAlgorithm
        ? ((CompositePublicKey) keyPair.getPublicKey()).getSecondKey()
        : keyPair.getPublicKey();
  }

  private static Address addressOf(final KeyPair keyPair) {
    return Address.extract(keyPair.getPublicKey());
  }

  private static BlockHeaderTestFixture fixture(final long number) {
    return new BlockHeaderTestFixture()
        .number(number)
        .blockHeaderFunctions(new CliqueBlockHeaderFunctions());
  }
}
