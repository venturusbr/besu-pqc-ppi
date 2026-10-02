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
package org.hyperledger.besu.ethereum.mainnet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.GasLimitCalculator;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.TransactionTestFixture;
import org.hyperledger.besu.ethereum.mainnet.feemarket.FeeMarket;
import org.hyperledger.besu.ethereum.transaction.TransactionInvalidReason;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Flexible code delegations are checked against the signer key resolved from the signature, not
 * the key the delegation carries: a hybrid carries only its ML-DSA half, and a delegation signed
 * with a fully recoverable algorithm carries no key at all.
 */
class FlexibleCodeDelegationValidationTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;
  private static final DSAParametersSet MLDSA = DSAParametersSet.MLDSA44;
  private static final DSAParametersSet SECP = DSAParametersSet.SECP256K1;
  private static final Address DELEGATE =
      Address.fromHexString("0x000000000000000000000000000000000000beef");

  private final GasCalculator gasCalculator = mock(GasCalculator.class);
  private MainnetTransactionValidator validator;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(SECP, MLDSA, HYBRID));
    config.setNodeActiveDSA(SECP.getName());
    DSAProviderFactory.setDsaProvider(config, null);

    when(gasCalculator.transactionIntrinsicGasCost(any(), anyLong())).thenReturn(50L);
    // built after the provider is set: the validator takes it in its constructor
    validator =
        new MainnetTransactionValidator(
            gasCalculator,
            GasLimitCalculator.constant(),
            FeeMarket.london(0L),
            false,
            Optional.of(BigInteger.ONE),
            Set.of(TransactionType.DELEGATE_CODE),
            Set.of(BlobType.KZG_PROOF),
            Integer.MAX_VALUE);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void acceptsAHybridDelegationCarryingOnlyItsMlDsaHalf() {
    final KeyPair signer = algorithm(HYBRID).generateNodeKeyPair();

    final CodeDelegation delegation =
        signed(HYBRID, Optional.of(mlDsaHalfOf(signer)), signer, false);

    assertThat(validate(delegation).isValid()).isTrue();
  }

  @Test
  void rejectsAHybridDelegationWhoseMlDsaHalfWasTamperedWith() {
    final KeyPair signer = algorithm(HYBRID).generateNodeKeyPair();

    final CodeDelegation delegation =
        signed(HYBRID, Optional.of(mlDsaHalfOf(signer)), signer, true);

    final ValidationResult<TransactionInvalidReason> result = validate(delegation);
    assertThat(result.isValid()).isFalse();
    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
  }

  @Test
  void theAuthorityOfAHybridDelegationIsTheWholeHybridKey() {
    final KeyPair signer = algorithm(HYBRID).generateNodeKeyPair();

    final CodeDelegation delegation =
        signed(HYBRID, Optional.of(mlDsaHalfOf(signer)), signer, false);

    assertThat(delegation.signerPublicKey().orElseThrow().getEncoded())
        .isEqualTo(signer.getPublicKey().getEncoded());
    assertThat(delegation.authorizer()).contains(Address.extract(signer.getPublicKey()));
  }

  @Test
  void acceptsAnMlDsaDelegation() {
    final KeyPair signer = algorithm(MLDSA).generateNodeKeyPair();

    final CodeDelegation delegation =
        signed(MLDSA, Optional.of(signer.getPublicKey()), signer, false);

    assertThat(validate(delegation).isValid()).isTrue();
  }

  @Test
  void rejectsAnMlDsaDelegationWhoseSignatureWasTamperedWith() {
    final KeyPair signer = algorithm(MLDSA).generateNodeKeyPair();

    final CodeDelegation delegation =
        signed(MLDSA, Optional.of(signer.getPublicKey()), signer, true);

    assertThat(validate(delegation).getInvalidReason())
        .isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
  }

  /** The key is recovered whole from the signature, so the delegation carries none. */
  @Test
  void acceptsASecp256k1FlexibleDelegationCarryingNoKey() {
    final KeyPair signer = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    final CodeDelegation delegation = signed(SECP, Optional.empty(), signer, false);

    assertThat(validate(delegation).isValid()).isTrue();
    assertThat(delegation.authorizer()).contains(Address.extract(signer.getPublicKey()));
  }

  private ValidationResult<TransactionInvalidReason> validate(final CodeDelegation delegation) {
    final Transaction transaction =
        new TransactionTestFixture()
            .type(TransactionType.DELEGATE_CODE)
            .chainId(Optional.of(BigInteger.ONE))
            .to(Optional.of(DELEGATE))
            .codeDelegations(List.of(delegation))
            .createTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair());
    return validator.validate(
        transaction,
        Optional.of(Wei.ONE),
        Optional.empty(),
        TransactionValidationParams.transactionPool());
  }

  /**
   * A delegation signed over its own signing hash. The hash does not cover the signature, so it is
   * taken from an otherwise identical delegation first.
   */
  private static CodeDelegation signed(
      final DSAParametersSet params,
      final Optional<PublicKey> carriedKey,
      final KeyPair signer,
      final boolean tamper) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final Bytes32 hash =
        delegation(params, carriedKey, dsa.sign(Bytes32.ZERO, signer.getPrivateKey()))
            .getOrComputeSenderRecoveryHash();

    Signature signature = dsa.sign(hash, signer.getPrivateKey());
    if (tamper) {
      // the last byte belongs to the ML-DSA signature, which is never recovered
      final byte[] bytes = signature.encodedBytes().toArray();
      bytes[bytes.length - 1] ^= 0x01;
      signature = SignatureFactory.createSignatureFromBytes(Bytes.wrap(bytes), params);
    }
    return delegation(params, carriedKey, signature);
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

  private static PublicKey mlDsaHalfOf(final KeyPair hybridKeyPair) {
    return ((CompositePublicKey) hybridKeyPair.getPublicKey()).getSecondKey();
  }

  private static DigitalSignatureAlgorithm algorithm(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }
}
