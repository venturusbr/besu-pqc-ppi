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
import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.types.FalconSignature;
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
 * A FLEXIBLE_EIP1559 transaction signed with Falcon-512, taken through the same encode, decode and
 * verify steps the network applies. Verification uses the call {@code MainnetTransactionValidator}
 * makes: the account-enabled algorithm for the declared DSA id, over the signing hash, against the
 * mounted public key.
 */
class FlexibleEIP1559Falcon512TransactionTest {

  private static final short FALCON512_ID = DSAParametersSet.FALCON512.getId();

  private final Falcon falcon = new Falcon(DSAParametersSet.FALCON512);

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    dsaConfig.buildAccountSupportedAlgorithms(
        List.of(DSAParametersSet.SECP256K1, DSAParametersSet.FALCON512));
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void falconTransactionSurvivesTheWireAndVerifies() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    final Transaction decoded = roundTrip(signed);

    assertThat(decoded.getType()).isEqualTo(TransactionType.FLEXIBLE_EIP1559);
    assertThat(decoded.getDsaType()).contains(FALCON512_ID);
    assertThat(decoded.getSignature())
        .isInstanceOf(FalconSignature.class)
        .isEqualTo(signed.getSignature());
    assertThat(decoded.getMountedPublicKey()).isEqualTo(keyPair.getPublicKey());
    assertThat(decoded.getSender()).isEqualTo(Address.extract(keyPair.getPublicKey()));
    assertThat(verifyAsTheValidatorDoes(decoded)).isTrue();
  }

  @Test
  void tamperingWithASignedFieldBreaksVerification() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    // Same signature and key, different value: the signing hash no longer matches.
    final Transaction tampered =
        unsigned(keyPair.getPublicKey(), Wei.of(999_999)).signature(signed.getSignature()).build();

    assertThat(verifyAsTheValidatorDoes(roundTrip(tampered))).isFalse();
  }

  @Test
  void anotherAccountsKeyCannotClaimTheTransaction() {
    final KeyPair signer = falcon.generateNodeKeyPair();
    final KeyPair impersonated = falcon.generateNodeKeyPair();
    final Transaction signed = sign(signer, Wei.of(1_000));

    // A non-recoverable algorithm trusts the carried key for the sender address, so only
    // verification stops someone else's key from being attached to this signature.
    final Transaction forged =
        unsigned(impersonated.getPublicKey(), Wei.of(1_000))
            .signature(signed.getSignature())
            .build();
    final Transaction decoded = roundTrip(forged);

    assertThat(decoded.getSender()).isEqualTo(Address.extract(impersonated.getPublicKey()));
    assertThat(verifyAsTheValidatorDoes(decoded)).isFalse();
  }

  private static Transaction sign(final KeyPair keyPair, final Wei value) {
    return unsigned(keyPair.getPublicKey(), value).signAndBuild(keyPair);
  }

  private static Transaction.Builder unsigned(final PublicKey publicKey, final Wei value) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(FALCON512_ID)
        .chainId(BigInteger.valueOf(1337))
        .nonce(7)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
        .value(value)
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(Optional.of(publicKey));
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
