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
package org.hyperledger.besu.crypto.pqc.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import org.junit.jupiter.api.Test;

class MetricWritersTest {

  @Test
  void aVerifyLineHasTheColumnsOfTheHeaderAndNothingAfterTheLast() {
    final String line =
        MetricWriters.verifyMetricsLine(
            1_234L, "qbft-commit", true, DSAParametersSet.SECP256K1MLDSA44);

    final String[] header = MetricWriters.buildVerifyHeader().trim().split(",", -1);
    assertThat(line).endsWith("qbft-commit\n");
    assertThat(line.trim().split(",", -1))
        .hasSameSizeAs(header)
        .containsExactly("1234", "yes", DSAParametersSet.SECP256K1MLDSA44.getName(), "qbft-commit");
  }

  @Test
  void aSignatureThatFailsIsRecordedAsNotValid() {
    final String line =
        MetricWriters.verifyMetricsLine(1L, "discv4-packet", false, DSAParametersSet.MLDSA44);

    assertThat(line.trim().split(",", -1)[1]).isEqualTo("no");
  }

  @Test
  void aTimedVerificationReturnsTheResultOfTheCheck() {
    assertThat(MetricWriters.timeVerification("node-record", DSAParametersSet.MLDSA44, () -> true))
        .isTrue();
    assertThat(MetricWriters.timeVerification("node-record", DSAParametersSet.MLDSA44, () -> false))
        .isFalse();
  }

  @Test
  void aPkrLineHasTheColumnsOfTheHeader() {
    final String line =
        MetricWriters.pkrMetricsLine(1_234L, "qbft-commit-seal", DSAParametersSet.SECP256K1);

    final String[] header = MetricWriters.buildPkrHeader().trim().split(",", -1);
    assertThat(line).endsWith("\n");
    assertThat(line.trim().split(",", -1))
        .hasSameSizeAs(header)
        .containsExactly("1234", DSAParametersSet.SECP256K1.getName(), "qbft-commit-seal");
  }

  @Test
  void aTimedRecoveryReturnsWhatWasRecovered() {
    assertThat(
            MetricWriters.timeRecovery("discv4-packet", DSAParametersSet.SECP256K1, () -> "key"))
        .isEqualTo("key");
  }

  @Test
  void everyFileEndsWithTheAlgorithmAndTheContext() {
    assertThat(MetricWriters.buildSignHeader())
        .isEqualTo("DSASigningTime(ns),Algorithm,Context\n");
    assertThat(MetricWriters.buildVerifyHeader())
        .isEqualTo("DSAVerificationTime(ns),isSignatureValid,Algorithm,Context\n");
    assertThat(MetricWriters.buildPkrHeader()).isEqualTo("PKRTime(ns),Algorithm,Context\n");
  }
}
