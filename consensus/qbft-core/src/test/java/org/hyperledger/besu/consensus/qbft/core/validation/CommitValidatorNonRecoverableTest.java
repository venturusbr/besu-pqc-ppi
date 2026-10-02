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
package org.hyperledger.besu.consensus.qbft.core.validation;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.common.bft.payload.SignedData;
import org.hyperledger.besu.consensus.qbft.core.payload.CommitPayload;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Commit messages under algorithms that cannot recover a key from a signature. The commit seal must
 * be attributed using the key the message carries; deriving it from the seal alone throws for these
 * algorithms, which stalled consensus on a SECP256K1-MLDSA44 network.
 */
class CommitValidatorNonRecoverableTest {

  private static final ConsensusRoundIdentifier ROUND = new ConsensusRoundIdentifier(1, 0);
  private static final Hash DIGEST = Hash.fromHexStringLenient("0x1");
  private static final Hash COMMIT_DIGEST = Hash.hash(Bytes.fromHexString("0x02"));

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
  void commitFromAPeerIsAccepted(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair validator = dsa.generateNodeKeyPair();
    final SignedData<CommitPayload> commit =
        receivedCommit(validator, sealBy(validator, COMMIT_DIGEST));

    assertThat(validatorFor(validator).validate(commit)).isTrue();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void ownCommitIsAccepted(final DSAParametersSet params) throws Exception {
    useAlgorithm(params);
    final KeyPair validator = dsa.generateNodeKeyPair();
    final CommitPayload payload =
        new CommitPayload(ROUND, DIGEST, sealBy(validator, COMMIT_DIGEST));

    // A node's own commit carries its full key, as MessageFactory attaches it.
    final SignedData<CommitPayload> commit =
        SignedData.createLocallySigned(
            payload, messageSignature(validator, payload), Optional.of(validator.getPublicKey()));

    assertThat(validatorFor(validator).validate(commit)).isTrue();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealOverTheWrongDigestIsRejectedWithoutThrowing(final DSAParametersSet params)
      throws Exception {
    useAlgorithm(params);
    final KeyPair validator = dsa.generateNodeKeyPair();
    final SignedData<CommitPayload> commit =
        receivedCommit(validator, sealBy(validator, Hash.hash(Bytes.fromHexString("0x09"))));

    assertThat(validatorFor(validator).validate(commit)).isFalse();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealMadeWithAnotherKeyIsRejectedWithoutThrowing(final DSAParametersSet params)
      throws Exception {
    useAlgorithm(params);
    final KeyPair validator = dsa.generateNodeKeyPair();
    final KeyPair other = dsa.generateNodeKeyPair();
    // The validator signs the message, but the seal inside it was made by someone else.
    final SignedData<CommitPayload> commit =
        receivedCommit(validator, sealBy(other, COMMIT_DIGEST));

    assertThat(validatorFor(validator).validate(commit)).isFalse();
  }

  private CommitValidator validatorFor(final KeyPair validator) {
    return new CommitValidator(
        List.of(Address.extract(validator.getPublicKey())), ROUND, DIGEST, COMMIT_DIGEST);
  }

  private Signature sealBy(final KeyPair signer, final Hash hash) {
    return dsa.sign(Bytes.wrap(hash.getBytes()), signer.getPrivateKey());
  }

  private Signature messageSignature(final KeyPair signer, final CommitPayload payload) {
    return dsa.sign(Bytes.wrap(payload.hashForSignature().getBytes()), signer.getPrivateKey());
  }

  /** A commit as decoded from a peer: it carries only the key that cannot be recovered. */
  private SignedData<CommitPayload> receivedCommit(final KeyPair author, final Signature seal) {
    final CommitPayload payload = new CommitPayload(ROUND, DIGEST, seal);
    final PublicKey carried =
        dsa instanceof HybridDigitalSignatureAlgorithm
            ? ((CompositePublicKey) author.getPublicKey()).getSecondKey()
            : author.getPublicKey();
    return SignedData.create(payload, messageSignature(author, payload), Optional.of(carried));
  }
}
