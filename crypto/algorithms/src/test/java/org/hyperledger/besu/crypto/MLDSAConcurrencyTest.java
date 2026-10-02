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
package org.hyperledger.besu.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * One MLDSA instance is shared by every thread of a node: discovery signs packets on several
 * worker threads at once while consensus signs on its own. The underlying signer accumulates the
 * message between init and generateSignature, so sharing one corrupted its state, surfacing as
 * "attempt to absorb with odd length queue" or an ArrayIndexOutOfBoundsException inside Keccak, and
 * at worst as a signature over the wrong message.
 */
class MLDSAConcurrencyTest {

  private static final int THREADS = 8;
  private static final int ROUNDS_PER_THREAD = 25;

  @Test
  void concurrentSignAndVerifyOnASharedInstanceStayCorrect() throws Exception {
    final MLDSA mldsa = new MLDSA(DSAParametersSet.MLDSA44);
    final KeyPair keyPair = mldsa.generateNodeKeyPair();

    final ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    try {
      final List<Callable<Boolean>> tasks = new ArrayList<>();
      for (int t = 0; t < THREADS; t++) {
        final int thread = t;
        tasks.add(
            () -> {
              for (int round = 0; round < ROUNDS_PER_THREAD; round++) {
                // each thread signs its own message, so a signature made over another thread's
                // data would fail to verify against this one
                final Bytes message = Bytes.ofUnsignedInt((long) thread * 1_000 + round);
                final Signature signature = mldsa.sign(message, keyPair.getPrivateKey());
                if (!mldsa.verify(message, signature, keyPair.getPublicKey())) {
                  return false;
                }
              }
              return true;
            });
      }
      for (final Future<Boolean> result : pool.invokeAll(tasks)) {
        assertThat(result.get()).isTrue();
      }
    } finally {
      pool.shutdownNow();
    }
  }
}
