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
package org.hyperledger.besu.ethereum.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@code signAndBuild} signs with the algorithm of the DSA type, and provides the part of the key
 * that algorithm cannot recover, so what it builds survives the encode, decode and verify steps the
 * network applies.
 */
class SignAndBuildTest {

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final Address DELEGATE =
      Address.fromHexString("0x000000000000000000000000000000000000beef");

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(
        List.of(
            DSAParametersSet.SECP256K1,
            DSAParametersSet.FALCON512,
            DSAParametersSet.MLDSA44,
            DSAParametersSet.SECP256K1MLDSA44,
            DSAParametersSet.SECP256K1FALCON512));
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"SECP256K1", "FALCON512", "MLDSA44", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void aSignedFlexibleTransactionDecodesAndVerifiesAsItsSigner(final DSAParametersSet params) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final KeyPair signer = dsa.generateNodeKeyPair();

    final Transaction signed = flexibleTransaction(params).signAndBuild(signer);
    final Transaction decoded = roundTrip(signed);

    assertThat(encoded(decoded.getMaybePublicKey()))
        .isEqualTo(encoded(expectedProvidedKey(params, signer)));
    assertThat(decoded.getSender()).isEqualTo(addressOf(signer)).isEqualTo(signed.getSender());
    assertThat(
            dsa.verify(
                Bytes.wrap(decoded.getSigningHash()),
                decoded.getSignature(),
                decoded.getMountedPublicKey()))
        .isTrue();
  }

  @Test
  void aKeyAlreadyProvidedIsKeptRatherThanReplaced() {
    final DigitalSignatureAlgorithm dsa = algorithm(DSAParametersSet.FALCON512);
    final KeyPair signer = dsa.generateNodeKeyPair();

    final Transaction signed =
        flexibleTransaction(DSAParametersSet.FALCON512)
            .providedPublicKey(Optional.of(signer.getPublicKey()))
            .signAndBuild(signer);

    assertThat(signed.getMaybePublicKey()).contains(signer.getPublicKey());
    assertThat(roundTrip(signed).getSender()).isEqualTo(addressOf(signer));
  }

  @Test
  void aTransactionWithoutDsaTypeIsStillSignedWithTheDefaultAlgorithm() {
    final KeyPair signer = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    final Transaction signed =
        new TransactionTestFixture()
            .type(TransactionType.EIP1559)
            .chainId(Optional.of(CHAIN_ID))
            .createTransaction(signer);

    assertThat(signed.getMaybePublicKey()).isEmpty();
    assertThat(roundTrip(signed).getSender()).isEqualTo(addressOf(signer));
  }

  @Test
  void aTransactionOfADsaTypeThatIsNotEnabledIsNotSigned() {
    final KeyPair signer = algorithm(DSAParametersSet.MLDSA65).generateNodeKeyPair();

    assertThatThrownBy(
            () -> flexibleTransaction(DSAParametersSet.MLDSA65).signAndBuild(signer))
        .hasMessageContaining("not enabled");
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"SECP256K1", "FALCON512", "MLDSA44", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void aSignedFlexibleDelegationDecodesAndVerifiesAsItsAuthorizer(final DSAParametersSet params) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final KeyPair signer = dsa.generateNodeKeyPair();

    final org.hyperledger.besu.datatypes.CodeDelegation signed =
        CodeDelegation.builder()
            .type(CodeDelegationType.FLEXIBLE)
            .dsaType(params.getId())
            .chainId(CHAIN_ID)
            .address(DELEGATE)
            .nonce(3L)
            .signAndBuild(signer);
    final org.hyperledger.besu.datatypes.CodeDelegation decoded =
        roundTrip(delegationTransaction(signed)).getCodeDelegationList().orElseThrow().get(0);

    assertThat(encoded(decoded.maybePublicKey()))
        .isEqualTo(encoded(expectedProvidedKey(params, signer)));
    assertThat(decoded.authorizer()).contains(addressOf(signer));
    assertThat(
            dsa.verify(
                decoded.getOrComputeSenderRecoveryHash(),
                decoded.signature(),
                decoded.signerPublicKey().orElseThrow()))
        .isTrue();
  }

  @Test
  void aSignedLegacyDelegationStillRecoversItsAuthorizer() {
    final KeyPair signer = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    final org.hyperledger.besu.datatypes.CodeDelegation signed =
        CodeDelegation.builder().chainId(CHAIN_ID).address(DELEGATE).nonce(3L).signAndBuild(signer);
    final org.hyperledger.besu.datatypes.CodeDelegation decoded =
        roundTrip(delegationTransaction(signed)).getCodeDelegationList().orElseThrow().get(0);

    assertThat(decoded.getType()).isEqualTo(CodeDelegationType.LEGACY);
    assertThat(decoded.maybePublicKey()).isEmpty();
    assertThat(decoded.authorizer()).contains(addressOf(signer));
  }

  @Test
  void aFlexibleDelegationWithoutDsaTypeIsNotSigned() {
    final KeyPair signer = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    assertThatThrownBy(
            () ->
                CodeDelegation.builder()
                    .type(CodeDelegationType.FLEXIBLE)
                    .address(DELEGATE)
                    .nonce(0L)
                    .signAndBuild(signer))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("DSA type");
  }

  /** What travels with the signature: the halves of the key that cannot be recovered from it. */
  private static Optional<PublicKey> expectedProvidedKey(
      final DSAParametersSet params, final KeyPair signer) {
    return switch (params) {
      case SECP256K1 -> Optional.empty();
      case FALCON512, MLDSA44 -> Optional.of(signer.getPublicKey());
      case SECP256K1MLDSA44, SECP256K1FALCON512 ->
          Optional.of(((CompositePublicKey) signer.getPublicKey()).getSecondKey());
      default -> throw new IllegalArgumentException("Unexpected " + params);
    };
  }

  /** Keys compared by encoding, since not every key type defines equality. */
  private static Optional<Bytes> encoded(final Optional<PublicKey> key) {
    return key.map(k -> Bytes.wrap(k.getEncoded()));
  }

  private static Transaction.Builder flexibleTransaction(final DSAParametersSet params) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(params.getId())
        .chainId(CHAIN_ID)
        .nonce(7)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(DELEGATE)
        .value(Wei.of(1_000))
        .payload(Bytes.EMPTY)
        .accessList(List.of());
  }

  private static Transaction delegationTransaction(
      final org.hyperledger.besu.datatypes.CodeDelegation delegation) {
    return new TransactionTestFixture()
        .type(TransactionType.DELEGATE_CODE)
        .chainId(Optional.of(CHAIN_ID))
        .to(Optional.of(DELEGATE))
        .codeDelegations(List.of(delegation))
        .createTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair());
  }

  private static Transaction roundTrip(final Transaction transaction) {
    return TransactionDecoder.decodeOpaqueBytes(
        TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.BLOCK_BODY),
        EncodingContext.BLOCK_BODY);
  }

  private static Address addressOf(final KeyPair signer) {
    return Address.extract(signer.getPublicKey());
  }

  private static DigitalSignatureAlgorithm algorithm(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }
}
