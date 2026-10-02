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
package org.hyperledger.besu.consensus.ibft.validation;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.common.bft.payload.Payload;
import org.hyperledger.besu.consensus.common.bft.payload.SignedData;
import org.hyperledger.besu.consensus.ibft.payload.CommitPayload;
import org.hyperledger.besu.consensus.ibft.payload.ProposalPayload;
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
 * IBFT 2.0 commit messages under algorithms that cannot recover a key from a signature. As in QBFT,
 * the commit seal must be attributed using the key the message carries; deriving it from the seal
 * alone throws for these algorithms and stalls consensus.
 */
class SignedDataValidatorNonRecoverableTest {

  private static final ConsensusRoundIdentifier ROUND = new ConsensusRoundIdentifier(1, 0);
  private static final Hash DIGEST = Hash.hash(Bytes.fromHexString("0x01"));

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
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final KeyPair validator = dsa.generateNodeKeyPair();
    final SignedDataValidator signedDataValidator = validatorWithProposal(proposer, validator);

    final SignedData<CommitPayload> commit =
        received(validator, new CommitPayload(ROUND, DIGEST, sealBy(validator, DIGEST)));

    assertThat(signedDataValidator.validateCommit(commit)).isTrue();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealOverTheWrongDigestIsRejectedWithoutThrowing(final DSAParametersSet params)
      throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final KeyPair validator = dsa.generateNodeKeyPair();
    final SignedDataValidator signedDataValidator = validatorWithProposal(proposer, validator);

    final Signature wrongSeal = sealBy(validator, Hash.hash(Bytes.fromHexString("0x09")));
    final SignedData<CommitPayload> commit =
        received(validator, new CommitPayload(ROUND, DIGEST, wrongSeal));

    assertThat(signedDataValidator.validateCommit(commit)).isFalse();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void sealMadeWithAnotherKeyIsRejectedWithoutThrowing(final DSAParametersSet params)
      throws Exception {
    useAlgorithm(params);
    final KeyPair proposer = dsa.generateNodeKeyPair();
    final KeyPair validator = dsa.generateNodeKeyPair();
    final SignedDataValidator signedDataValidator = validatorWithProposal(proposer, validator);

    // The validator signs the message, but the seal inside it was made by the proposer.
    final SignedData<CommitPayload> commit =
        received(validator, new CommitPayload(ROUND, DIGEST, sealBy(proposer, DIGEST)));

    assertThat(signedDataValidator.validateCommit(commit)).isFalse();
  }

  private SignedDataValidator validatorWithProposal(
      final KeyPair proposer, final KeyPair validator) {
    final Address proposerAddress = Address.extract(proposer.getPublicKey());
    final SignedDataValidator signedDataValidator =
        new SignedDataValidator(
            List.of(proposerAddress, Address.extract(validator.getPublicKey())),
            proposerAddress,
            ROUND);
    assertThat(
            signedDataValidator.validateProposal(
                received(proposer, new ProposalPayload(ROUND, DIGEST))))
        .isTrue();
    return signedDataValidator;
  }

  private Signature sealBy(final KeyPair signer, final Hash hash) {
    return dsa.sign(Bytes.wrap(hash.getBytes()), signer.getPrivateKey());
  }

  /** A message as decoded from a peer: it carries only the key that cannot be recovered. */
  private <P extends Payload> SignedData<P> received(final KeyPair author, final P payload) {
    final PublicKey carried =
        dsa instanceof HybridDigitalSignatureAlgorithm
            ? ((CompositePublicKey) author.getPublicKey()).getSecondKey()
            : author.getPublicKey();
    final Signature signature =
        dsa.sign(Bytes.wrap(payload.hashForSignature().getBytes()), author.getPrivateKey());
    return SignedData.create(payload, signature, Optional.of(carried));
  }
}
