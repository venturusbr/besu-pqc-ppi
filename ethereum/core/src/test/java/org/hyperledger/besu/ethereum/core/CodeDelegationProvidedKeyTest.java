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
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A code delegation built from JSON follows the same rule as one decoded from RLP: only the half
 * of a hybrid key that cannot be recovered may be provided.
 */
class CodeDelegationProvidedKeyTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private final DigitalSignatureAlgorithm hybrid =
      new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();

  @BeforeEach
  void enableHybridDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void acceptsTheHalfThatCannotBeRecovered() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Bytes mlDsaHalf =
        Bytes.wrap(((CompositePublicKey) keyPair.getPublicKey()).getSecondKey().getEncoded());

    final CodeDelegation codeDelegation = (CodeDelegation) fromJson(mlDsaHalf, signatureBy(keyPair));

    assertThat(codeDelegation.maybePublicKey()).isPresent();
    assertThat(codeDelegation.maybePublicKey().get().getEncoded()).isEqualTo(mlDsaHalf.toArray());
  }

  @Test
  void rejectsTheWholeCompositeKey() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Bytes wholeKey = Bytes.wrap(keyPair.getPublicKey().getEncoded());

    assertThatThrownBy(() -> fromJson(wholeKey, signatureBy(keyPair)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private Bytes signatureBy(final KeyPair keyPair) {
    return hybrid
        .sign(Hash.keccak256(Bytes.fromHexString("0xc0ffee")), keyPair.getPrivateKey())
        .encodedBytes();
  }

  private static org.hyperledger.besu.datatypes.CodeDelegation fromJson(
      final Bytes publicKey, final Bytes signature) {
    return CodeDelegation.createCodeDelegation(
        CodeDelegationType.FLEXIBLE,
        HYBRID.getId(),
        BigInteger.ONE,
        Address.fromHexString("0x000000000000000000000000000000000000beef"),
        "0x00",
        publicKey,
        signature,
        null,
        null,
        null);
  }
}
