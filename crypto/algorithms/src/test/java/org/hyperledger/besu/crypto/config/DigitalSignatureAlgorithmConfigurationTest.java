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
package org.hyperledger.besu.crypto.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Every transaction decode and signature check looks its algorithm up by id, so the enabled
 * algorithms are built once, with the configuration, and one instance serves every thread.
 */
class DigitalSignatureAlgorithmConfigurationTest {

  private static final List<DSAParametersSet> ENABLED =
      List.of(
          DSAParametersSet.SECP256K1,
          DSAParametersSet.MLDSA44,
          DSAParametersSet.FALCON512,
          DSAParametersSet.SECP256K1MLDSA44,
          DSAParametersSet.SECP256K1FALCON512);

  private DigitalSignatureAlgorithmConfiguration config;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    config = new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(ENABLED);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"SECP256K1", "MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void looksUpTheSameInstanceEveryTime(final DSAParametersSet params) {
    final DigitalSignatureAlgorithm first = config.getEnabledDSA(params.getId());

    assertThat(config.getEnabledDSA(params.getId())).isSameAs(first);
    assertThat(first.getDsaParametersSet()).isEqualTo(params);
  }

  @Test
  void anAlgorithmThatIsNotEnabledStillFailsTheLookup() {
    assertThatThrownBy(() -> config.getEnabledDSA(DSAParametersSet.MLDSA87.getId()))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void keepsTheEnabledAlgorithmsNamed() {
    assertThat(config.getAccountsSupportedDSANames())
        .containsExactlyInAnyOrderElementsOf(
            ENABLED.stream().map(DSAParametersSet::getName).toList());
  }

  /**
   * The shared instance is used by the pool, block selection and block processing at once, so it
   * must give every thread the right answer, for signatures that hold and ones that do not.
   */
  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void oneInstanceSignsAndVerifiesCorrectlyFromManyThreads(final DSAParametersSet params)
      throws Exception {
    final DigitalSignatureAlgorithm dsa = config.getEnabledDSA(params.getId());
    final int threads = 8;
    final int rounds = 25;

    final ExecutorService pool = Executors.newFixedThreadPool(threads);
    final CountDownLatch start = new CountDownLatch(1);
    final List<Future<?>> futures = new ArrayList<>();
    for (int t = 0; t < threads; t++) {
      final int thread = t;
      futures.add(
          pool.submit(
              () -> {
                final KeyPair keyPair = dsa.generateNodeKeyPair();
                final KeyPair other = dsa.generateNodeKeyPair();
                start.await();
                for (int i = 0; i < rounds; i++) {
                  final Bytes32 hash = Hash.keccak256(Bytes.ofUnsignedInt(thread * 1_000 + i));
                  final Signature signature = dsa.sign(hash, keyPair.getPrivateKey());
                  assertThat(dsa.verify(hash, signature, keyPair.getPublicKey())).isTrue();
                  assertThat(dsa.verify(hash, signature, other.getPublicKey())).isFalse();
                  assertThat(
                          dsa.verify(
                              Hash.keccak256(hash), signature, keyPair.getPublicKey()))
                      .isFalse();
                }
                return null;
              }));
    }
    start.countDown();
    try {
      for (final Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
  }
}
