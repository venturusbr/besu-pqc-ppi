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

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;

import java.security.InvalidAlgorithmParameterException;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Commit seals under an algorithm that cannot recover the signer from the signature. Carrying the
 * public key alongside the seal is what makes the committer's address derivable at all, but it is
 * also what makes verification mandatory: a public key is public, so anyone can attach a
 * validator's key to a signature that validator never produced.
 */
class CommitSealTest {

  private static final Hash COMMIT_HASH =
      Hash.hash(Bytes.fromHexStringLenient("0x1337deadbeef1337"));

  private final DigitalSignatureAlgorithm mldsa = new MLDSA(DSAParametersSet.MLDSA44);

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.MLDSA44.getName());
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void mldsaIsNotRecoverableOtherwiseTheseTestsProveNothing() {
    assertThat(DSAProviderFactory.getActiveDSA()).isNotInstanceOf(PublicKeyRecoverable.class);
  }

  @Test
  void genuineSealYieldsItsSignersAddress() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final CommitSeal seal = sealOver(COMMIT_HASH, keyPair);

    assertThat(seal.recoverVerifiedAuthor(COMMIT_HASH))
        .contains(Address.extract(keyPair.getPublicKey()));
  }

  @Test
  void sealOverDifferentDataIsNotCounted() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final CommitSeal seal = sealOver(Hash.hash(Bytes.fromHexStringLenient("0xfeedface")), keyPair);

    // A genuine signature by a genuine validator, but not over this block.
    assertThat(seal.recoverVerifiedAuthor(COMMIT_HASH)).isEmpty();
  }

  @Test
  void sealPresentedWithSomeoneElsesKeyIsNotCounted() {
    final KeyPair signer = mldsa.generateNodeKeyPair();
    final KeyPair impersonated = mldsa.generateNodeKeyPair();
    final Signature signature =
        mldsa.sign(Bytes.wrap(COMMIT_HASH.getBytes()), signer.getPrivateKey());

    final CommitSeal seal = new CommitSeal(signature, Optional.of(impersonated.getPublicKey()));

    assertThat(seal.recoverVerifiedAuthor(COMMIT_HASH)).isEmpty();
  }

  @Test
  void fabricatedSealCarryingAGenuineValidatorKeyIsNotCounted() {
    // The forgery this verification exists to stop: without it, resolvePublicKey trusts the
    // carried key and Address.extract hands back a real validator's address for a seal that
    // validator never produced, manufacturing quorum out of nothing.
    final KeyPair validator = mldsa.generateNodeKeyPair();
    final Signature garbage =
        mldsa.sign(Bytes.fromHexStringLenient("0x00"), mldsa.generateNodeKeyPair().getPrivateKey());

    final CommitSeal forged = new CommitSeal(garbage, Optional.of(validator.getPublicKey()));

    assertThat(Address.extract(validator.getPublicKey()))
        .isEqualTo(Address.extract(forged.getPublicKey().get()));
    assertThat(forged.recoverVerifiedAuthor(COMMIT_HASH)).isEmpty();
  }

  @Test
  void sealWithNoKeyIsNotCountedWhenTheAlgorithmCannotRecoverOne() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final Signature signature =
        mldsa.sign(Bytes.wrap(COMMIT_HASH.getBytes()), keyPair.getPrivateKey());

    // Previously this threw out of block validation rather than rejecting the block.
    assertThat(new CommitSeal(signature).recoverVerifiedAuthor(COMMIT_HASH)).isEmpty();
  }

  private CommitSeal sealOver(final Hash hash, final KeyPair keyPair) {
    return new CommitSeal(
        mldsa.sign(Bytes.wrap(hash.getBytes()), keyPair.getPrivateKey()),
        Optional.of(keyPair.getPublicKey()));
  }
}
