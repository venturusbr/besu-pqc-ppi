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
package org.hyperledger.besu.consensus.qbft;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.consensus.common.bft.BftExtraData;
import org.hyperledger.besu.consensus.common.bft.CommitSeal;
import org.hyperledger.besu.consensus.common.bft.Vote;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Round-tripping of commit seals through the extraData field, with and without carried keys. */
class QbftExtraDataCodecSealEncodingTest {

  private static final Bytes VANITY_DATA = Bytes.wrap(new byte[32]);
  private static final List<Address> VALIDATORS =
      List.of(Address.fromHexString("1"), Address.fromHexString("2"));
  private static final Optional<Vote> VOTE = Optional.of(Vote.authVote(Address.fromHexString("1")));
  private static final int ROUND = 5;

  private final QbftExtraDataCodec codec = new QbftExtraDataCodec();

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  private void useMlDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.MLDSA44.getName());
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
  }

  @Test
  void mlDsaSealsAndTheirKeysSurviveARoundTrip() throws InvalidAlgorithmParameterException {
    useMlDsa();
    final DigitalSignatureAlgorithm mldsa = new MLDSA(DSAParametersSet.MLDSA44);
    final KeyPair first = mldsa.generateNodeKeyPair();
    final KeyPair second = mldsa.generateNodeKeyPair();

    final List<CommitSeal> seals = List.of(sealFor(mldsa, first), sealFor(mldsa, second));

    final BftExtraData decoded =
        codec.decodeRaw(
            codec.encode(new BftExtraData(VANITY_DATA, seals, VOTE, ROUND, VALIDATORS)));

    // MLDSASignature and MLDSAPublicKey do not implement equals, so compare their encodings.
    assertThat(decoded.getSeals()).hasSize(2);
    assertThat(decoded.getSeals().stream().map(s -> s.getSignature().encodedBytes()).toList())
        .containsExactlyElementsOf(
            seals.stream().map(s -> s.getSignature().encodedBytes()).toList());
    assertThat(
            decoded.getSeals().stream()
                .map(s -> s.getPublicKey().orElseThrow().getEncoded())
                .toList())
        .containsExactlyElementsOf(
            seals.stream().map(s -> s.getPublicKey().orElseThrow().getEncoded()).toList());
    assertThat(decoded.getRound()).isEqualTo(ROUND);
    assertThat(decoded.getValidators()).isEqualTo(VALIDATORS);
  }

  @Test
  void secpEncodingIsUnchangedByTheKeyCarryingField() {
    // SECP256K1 recovers its signer, so no key is written and existing chains' extraData bytes
    // are unaffected. Supplying a key must make no difference to the encoding.
    final var secp = SignatureAlgorithmFactory.getInstance();
    final KeyPair keyPair = secp.generateKeyPair();
    final var signature = secp.createSignature(BigInteger.ONE, BigInteger.TEN, (byte) 0);

    final Bytes withoutKey =
        codec.encode(
            new BftExtraData(
                VANITY_DATA, List.of(new CommitSeal(signature)), VOTE, ROUND, VALIDATORS));
    final Bytes withKey =
        codec.encode(
            new BftExtraData(
                VANITY_DATA,
                List.of(new CommitSeal(signature, Optional.of(keyPair.getPublicKey()))),
                VOTE,
                ROUND,
                VALIDATORS));

    assertThat(withKey).isEqualTo(withoutKey);
    assertThat(codec.decodeRaw(withKey).getSeals()).containsExactly(new CommitSeal(signature));
  }

  @Test
  void sealsAreOmittedFromTheHashedEncodingRegardlessOfCarriedKeys()
      throws InvalidAlgorithmParameterException {
    useMlDsa();
    final DigitalSignatureAlgorithm mldsa = new MLDSA(DSAParametersSet.MLDSA44);
    final BftExtraData withSeals =
        new BftExtraData(
            VANITY_DATA,
            List.of(sealFor(mldsa, mldsa.generateNodeKeyPair())),
            VOTE,
            ROUND,
            VALIDATORS);
    final BftExtraData withoutSeals =
        new BftExtraData(VANITY_DATA, List.of(), VOTE, ROUND, VALIDATORS);

    // The block hash must not depend on which validators sealed it, nor on their keys.
    assertThat(codec.encodeWithoutCommitSealsAndRoundNumber(withSeals))
        .isEqualTo(codec.encodeWithoutCommitSealsAndRoundNumber(withoutSeals));
  }

  private CommitSeal sealFor(final DigitalSignatureAlgorithm dsa, final KeyPair keyPair) {
    return new CommitSeal(
        dsa.sign(Bytes.fromHexStringLenient("0xabcdef"), keyPair.getPrivateKey()),
        Optional.of(keyPair.getPublicKey()));
  }
}
