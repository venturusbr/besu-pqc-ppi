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
package org.hyperledger.besu.ethereum.core.encoding;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A FLEXIBLE_EIP1559 transaction signed with SECP256K1-FALCON512, taken through encode, decode and
 * the verification call {@code MainnetTransactionValidator} makes.
 *
 * <p>The transaction carries only the Falcon-512 half of the public key; the SECP256K1 half is
 * recovered from its signature. The signing hash covers the provided key as given, so the
 * transaction must be built with that Falcon-only key for the hash to match after decoding.
 */
class FlexibleEIP1559Secp256k1Falcon512TransactionTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1FALCON512;

  private DigitalSignatureAlgorithm hybrid;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    dsaConfig.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
    hybrid = DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(HYBRID.getId());
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void hybridTransactionSurvivesTheWireAndVerifies() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    final Transaction decoded = roundTrip(signed);

    assertThat(decoded.getDsaType()).contains(HYBRID.getId());
    assertThat(decoded.getSignature()).isInstanceOf(CompositeSignature.class);
    assertThat(decoded.getSignature().encodedBytes()).isEqualTo(signed.getSignature().encodedBytes());
    // The SECP256K1 half was recovered; together with the carried Falcon half it is the full key.
    assertThat(decoded.getMountedPublicKey().getEncoded())
        .isEqualTo(keyPair.getPublicKey().getEncoded());
    assertThat(decoded.getSender()).isEqualTo(Address.extract(keyPair.getPublicKey()));
    assertThat(verifyAsTheValidatorDoes(decoded)).isTrue();
  }

  @Test
  void tamperingWithASignedFieldBreaksVerification() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    final Transaction tampered =
        unsigned(falconHalf(keyPair), Wei.of(999_999)).signature(signed.getSignature()).build();

    assertThat(verifyAsTheValidatorDoes(roundTrip(tampered))).isFalse();
  }

  @Test
  void anotherAccountsFalconKeyCannotClaimTheTransaction() {
    final KeyPair signer = hybrid.generateNodeKeyPair();
    final KeyPair impersonated = hybrid.generateNodeKeyPair();
    final Transaction signed = sign(signer, Wei.of(1_000));

    final Transaction forged =
        unsigned(falconHalf(impersonated), Wei.of(1_000))
            .signature(signed.getSignature())
            .build();

    assertThat(verifyAsTheValidatorDoes(roundTrip(forged))).isFalse();
  }

  private Transaction sign(final KeyPair keyPair, final Wei value) {
    // Transaction.Builder#signAndBuild always signs with SECP256K1, so sign the hash directly.
    // The signing hash covers every field but the signature, so any placeholder will do.
    final Signature placeholder = hybrid.sign(Bytes.wrap(new byte[32]), keyPair.getPrivateKey());
    final Bytes signingHash =
        Bytes.wrap(
            unsigned(falconHalf(keyPair), value)
                .signature(placeholder)
                .build()
                .getSigningHash());
    final Signature signature = hybrid.sign(signingHash, keyPair.getPrivateKey());
    return unsigned(falconHalf(keyPair), value).signature(signature).build();
  }

  private static PublicKey falconHalf(final KeyPair keyPair) {
    return ((CompositePublicKey) keyPair.getPublicKey()).getSecondKey();
  }

  private static Transaction.Builder unsigned(final PublicKey providedPublicKey, final Wei value) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(HYBRID.getId())
        .chainId(BigInteger.valueOf(1337))
        .nonce(7)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
        .value(value)
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(Optional.of(providedPublicKey));
  }

  private static Transaction roundTrip(final Transaction transaction) {
    return TransactionDecoder.decodeOpaqueBytes(
        TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.BLOCK_BODY),
        EncodingContext.BLOCK_BODY);
  }

  private static boolean verifyAsTheValidatorDoes(final Transaction transaction) {
    final DigitalSignatureAlgorithm dsa =
        DSAProviderFactory.getVerifierProvider()
            .getAccountEnabledDSAById(transaction.getDsaType().orElseThrow());
    return dsa.verify(
        Bytes.wrap(transaction.getSigningHash()),
        transaction.getSignature(),
        transaction.getMountedPublicKey());
  }
}
