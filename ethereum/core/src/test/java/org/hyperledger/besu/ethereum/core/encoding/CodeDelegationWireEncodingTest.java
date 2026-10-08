/*
 * Copyright contributors to Besu.
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
package org.hyperledger.besu.ethereum.core.encoding;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.TransactionTestFixture;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A transaction carrying code delegations has to survive the trip to the pool, to peers and into a
 * block: whatever the node encodes, it must be able to decode back into the same delegations.
 */
class CodeDelegationWireEncodingTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;
  private static final DSAParametersSet SECP = DSAParametersSet.SECP256K1;
  private static final Address DELEGATE =
      Address.fromHexString("0x000000000000000000000000000000000000beef");

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(SECP, HYBRID));
    config.setNodeActiveDSA(SECP.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void aTransactionWithLegacyAndFlexibleDelegationsDecodesBackToTheSameDelegations() {
    final KeyPair hybridSigner = algorithm(HYBRID).generateNodeKeyPair();
    final KeyPair secpSigner = SignatureAlgorithmFactory.getInstance().generateKeyPair();
    final List<org.hyperledger.besu.datatypes.CodeDelegation> delegations =
        List.of(
            legacy(secpSigner),
            flexible(
                HYBRID,
                Optional.of(((CompositePublicKey) hybridSigner.getPublicKey()).getSecondKey()),
                hybridSigner),
            flexible(SECP, Optional.empty(), secpSigner));

    final Transaction transaction =
        new TransactionTestFixture()
            .type(TransactionType.DELEGATE_CODE)
            .chainId(Optional.of(BigInteger.ONE))
            .to(Optional.of(DELEGATE))
            .codeDelegations(delegations)
            .createTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair());

    for (final EncodingContext context :
        List.of(EncodingContext.POOLED_TRANSACTION, EncodingContext.BLOCK_BODY)) {
      final Bytes encoded = TransactionEncoder.encodeOpaqueBytes(transaction, context);
      final Transaction decoded = TransactionDecoder.decodeOpaqueBytes(encoded, context);

      final List<org.hyperledger.besu.datatypes.CodeDelegation> decodedDelegations =
          decoded.getCodeDelegationList().orElseThrow();
      assertThat(decodedDelegations).hasSize(delegations.size());
      for (int i = 0; i < delegations.size(); i++) {
        assertSameDelegation(decodedDelegations.get(i), delegations.get(i));
      }
      assertThat(decoded.getHash()).isEqualTo(transaction.getHash());
    }
  }

  /**
   * The pool keeps a detached copy of each transaction, and block creation encodes that copy, so
   * the copy has to keep every delegation as it was: type, DSA type and public key included.
   */
  @Test
  void aDetachedCopyKeepsFlexibleDelegationsIntact() {
    final KeyPair hybridSigner = algorithm(HYBRID).generateNodeKeyPair();
    final org.hyperledger.besu.datatypes.CodeDelegation delegation =
        flexible(
            HYBRID,
            Optional.of(((CompositePublicKey) hybridSigner.getPublicKey()).getSecondKey()),
            hybridSigner);
    final Transaction transaction =
        new TransactionTestFixture()
            .type(TransactionType.DELEGATE_CODE)
            .chainId(Optional.of(BigInteger.ONE))
            .to(Optional.of(DELEGATE))
            .codeDelegations(List.of(delegation))
            .createTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair());

    final Transaction copy = transaction.detachedCopy();

    assertSameDelegation(copy.getCodeDelegationList().orElseThrow().get(0), delegation);
    assertThat(
            TransactionEncoder.encodeOpaqueBytes(copy, EncodingContext.BLOCK_BODY))
        .isEqualTo(TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.BLOCK_BODY));
  }

  private static void assertSameDelegation(
      final org.hyperledger.besu.datatypes.CodeDelegation actual,
      final org.hyperledger.besu.datatypes.CodeDelegation expected) {
    assertThat(actual.getType()).isEqualTo(expected.getType());
    assertThat(actual.dsaType()).isEqualTo(expected.dsaType());
    assertThat(actual.chainId()).isEqualTo(expected.chainId());
    assertThat(actual.address()).isEqualTo(expected.address());
    assertThat(actual.nonce()).isEqualTo(expected.nonce());
    assertThat(actual.publicKey()).isEqualTo(expected.publicKey());
    assertThat(actual.signature().encodedBytes()).isEqualTo(expected.signature().encodedBytes());
    assertThat(actual.authorizer()).isEqualTo(expected.authorizer());
  }

  private static org.hyperledger.besu.datatypes.CodeDelegation legacy(final KeyPair signer) {
    return CodeDelegation.builder()
        .chainId(BigInteger.ONE)
        .address(DELEGATE)
        .nonce(0L)
        .signAndBuild(signer);
  }

  /** Signed over its own signing hash, which does not cover the signature. */
  private static CodeDelegation flexible(
      final DSAParametersSet params, final Optional<PublicKey> carriedKey, final KeyPair signer) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final Bytes32 hash =
        delegation(params, carriedKey, dsa.sign(Bytes32.ZERO, signer.getPrivateKey()))
            .getOrComputeSenderRecoveryHash();
    return delegation(params, carriedKey, dsa.sign(hash, signer.getPrivateKey()));
  }

  private static CodeDelegation delegation(
      final DSAParametersSet params,
      final Optional<PublicKey> carriedKey,
      final Signature signature) {
    return new CodeDelegation(
        CodeDelegationType.FLEXIBLE,
        Optional.of(params.getId()),
        BigInteger.ONE,
        DELEGATE,
        0L,
        carriedKey,
        signature);
  }

  private static DigitalSignatureAlgorithm algorithm(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }
}
