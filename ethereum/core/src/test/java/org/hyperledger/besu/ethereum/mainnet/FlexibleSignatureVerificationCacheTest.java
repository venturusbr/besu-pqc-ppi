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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.GasLimitCalculator;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
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
 * A transaction's signature is checked from several decoded copies of it -- on admission to the
 * pool, on selection, on proposal validation and on import -- so a successful verification is
 * remembered by the transaction hash, and a copy whose sender is known does not resolve its key
 * again. Neither may let a signature vouch for anything but the exact bytes that verified.
 */
class FlexibleSignatureVerificationCacheTest {

  private static final DSAParametersSet SECP = DSAParametersSet.SECP256K1;
  private static final DSAParametersSet MLDSA = DSAParametersSet.MLDSA44;
  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final Address RECIPIENT =
      Address.fromHexString("0x000000000000000000000000000000000000beef");

  private MainnetTransactionValidator validator;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(SECP, MLDSA, HYBRID));
    config.setNodeActiveDSA(SECP.getName());
    DSAProviderFactory.setDsaProvider(config, null);

    // built after the provider is set: the validator takes it in its constructor
    validator =
        new MainnetTransactionValidator(
            mock(GasCalculator.class),
            GasLimitCalculator.constant(),
            FeeMarket.london(0L),
            false,
            Optional.of(CHAIN_ID),
            Set.of(TransactionType.FLEXIBLE_EIP1559),
            Set.of(BlobType.KZG_PROOF),
            Integer.MAX_VALUE);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void acceptsACopyOfAVerifiedTransactionWithoutResolvingItsKeyAgain() {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    final Transaction transaction =
        signed(MLDSA, sender, Optional.of(sender.getPublicKey()), Wei.of(1));
    assertThat(validator.validateTransactionSignature(transaction).isValid()).isTrue();

    final Transaction copy = spy(roundTrip(transaction));

    assertThat(validator.validateTransactionSignature(copy).isValid()).isTrue();
    assertThat(copy.getSender()).isEqualTo(Address.extract(sender.getPublicKey()));
    verify(copy, never()).getMountedPublicKey();
  }

  @Test
  void acceptsACopyOfAVerifiedHybridTransactionWithoutRecoveringItsKeyAgain() {
    final KeyPair sender = algorithm(HYBRID).generateNodeKeyPair();
    final Transaction transaction =
        signed(HYBRID, sender, Optional.of(mlDsaHalfOf(sender)), Wei.of(1));
    assertThat(validator.validateTransactionSignature(transaction).isValid()).isTrue();

    final Transaction copy = spy(roundTrip(transaction));

    assertThat(validator.validateTransactionSignature(copy).isValid()).isTrue();
    assertThat(copy.getSender()).isEqualTo(Address.extract(sender.getPublicKey()));
    verify(copy, never()).getMountedPublicKey();
  }

  @Test
  void aVerifiedTransactionDoesNotVouchForAnotherSignatureOverTheSameKey() {
    final KeyPair attacker = algorithm(MLDSA).generateNodeKeyPair();
    final KeyPair victim = algorithm(MLDSA).generateNodeKeyPair();
    final Transaction genuine =
        signed(MLDSA, victim, Optional.of(victim.getPublicKey()), Wei.of(1));
    assertThat(validator.validateTransactionSignature(genuine).isValid()).isTrue();

    // Same fields and the same carried key, so the same sender, signed by someone else.
    final Transaction forged =
        signed(MLDSA, attacker, Optional.of(victim.getPublicKey()), Wei.of(1));
    assertThat(forged.getSender()).isEqualTo(genuine.getSender());

    assertInvalidSignature(forged);
  }

  @Test
  void aVerifiedSignatureDoesNotVouchForChangedFields() {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    final Transaction genuine =
        signed(MLDSA, sender, Optional.of(sender.getPublicKey()), Wei.of(1));
    assertThat(validator.validateTransactionSignature(genuine).isValid()).isTrue();

    final Transaction tampered =
        unsigned(MLDSA, Optional.of(sender.getPublicKey()), Wei.of(1_000_000))
            .signature(genuine.getSignature())
            .build();

    assertInvalidSignature(tampered);
  }

  @Test
  void aVerifiedHybridTransactionDoesNotVouchForATamperedMlDsaHalf() {
    final KeyPair sender = algorithm(HYBRID).generateNodeKeyPair();
    final Optional<PublicKey> mlDsaHalf = Optional.of(mlDsaHalfOf(sender));
    final Transaction genuine = signed(HYBRID, sender, mlDsaHalf, Wei.of(1));
    assertThat(validator.validateTransactionSignature(genuine).isValid()).isTrue();

    // the last byte belongs to the ML-DSA signature, which is never recovered
    final byte[] bytes = genuine.getSignature().encodedBytes().toArray();
    bytes[bytes.length - 1] ^= 0x01;
    final Transaction tampered =
        unsigned(HYBRID, mlDsaHalf, Wei.of(1))
            .signature(SignatureFactory.createSignatureFromBytes(Bytes.wrap(bytes), HYBRID))
            .build();

    assertInvalidSignature(tampered);
  }

  @Test
  void aFailedVerificationIsNotRemembered() {
    final KeyPair attacker = algorithm(MLDSA).generateNodeKeyPair();
    final KeyPair victim = algorithm(MLDSA).generateNodeKeyPair();
    final Transaction forged =
        signed(MLDSA, attacker, Optional.of(victim.getPublicKey()), Wei.of(1));

    assertInvalidSignature(forged);
    // A copy is checked from scratch, and fails again rather than being taken as settled.
    assertInvalidSignature(roundTrip(forged));
  }

  /** The signer key is recovered whole from the signature, which authenticates it. */
  @Test
  void stillAcceptsASecp256k1FlexibleTransactionAndItsCopies() {
    final KeyPair sender = algorithm(SECP).generateNodeKeyPair();
    final Transaction transaction =
        signed(SECP, sender, Optional.of(sender.getPublicKey()), Wei.of(1));

    assertThat(validator.validateTransactionSignature(transaction).isValid()).isTrue();
    assertThat(validator.validateTransactionSignature(roundTrip(transaction)).isValid()).isTrue();
    assertThat(roundTrip(transaction).getSender())
        .isEqualTo(Address.extract(sender.getPublicKey()));
  }

  @Test
  void aCopyNeverSeenBeforeStillResolvesItsSenderFromItsKey() {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    final Transaction transaction =
        roundTrip(signed(MLDSA, sender, Optional.of(sender.getPublicKey()), Wei.of(42)));

    assertThat(transaction.getSender()).isEqualTo(Address.extract(sender.getPublicKey()));
  }

  private void assertInvalidSignature(final Transaction transaction) {
    final ValidationResult<TransactionInvalidReason> result =
        validator.validateTransactionSignature(transaction);
    assertThat(result.isValid()).isFalse();
    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
  }

  /**
   * A transaction carrying {@code carriedKey}, signed by {@code signer} over its signing hash. The
   * hash does not cover the signature, so it is taken from an otherwise identical transaction.
   */
  private static Transaction signed(
      final DSAParametersSet params,
      final KeyPair signer,
      final Optional<PublicKey> carriedKey,
      final Wei value) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final Bytes signingHash =
        Bytes.wrap(
            unsigned(params, carriedKey, value)
                .signature(dsa.sign(Bytes32.ZERO, signer.getPrivateKey()))
                .build()
                .getSigningHash());
    final Signature signature = dsa.sign(signingHash, signer.getPrivateKey());
    return unsigned(params, carriedKey, value).signature(signature).build();
  }

  private static Transaction.Builder unsigned(
      final DSAParametersSet params, final Optional<PublicKey> carriedKey, final Wei value) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(params.getId())
        .chainId(CHAIN_ID)
        .nonce(0)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(10))
        .gasLimit(21_000)
        .to(RECIPIENT)
        .value(value)
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(carriedKey);
  }

  /** A fresh instance from the transaction's bytes, as a peer's copy would arrive. */
  private static Transaction roundTrip(final Transaction transaction) {
    return TransactionDecoder.decodeOpaqueBytes(
        TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.BLOCK_BODY),
        EncodingContext.BLOCK_BODY);
  }

  private static PublicKey mlDsaHalfOf(final KeyPair hybridKeyPair) {
    return ((CompositePublicKey) hybridKeyPair.getPublicKey()).getSecondKey();
  }

  private static DigitalSignatureAlgorithm algorithm(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }
}
