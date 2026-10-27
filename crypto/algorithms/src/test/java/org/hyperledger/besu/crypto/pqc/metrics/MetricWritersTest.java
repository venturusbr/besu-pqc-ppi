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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class MetricWritersTest {

  private static final SupportedAlgorithms ALGORITHMS = new SupportedAlgorithms();

  @Test
  void aVerifyLineHasTheColumnsOfTheHeaderAndNothingAfterTheLast() {
    final String line =
        MetricWriters.verifyMetricsLine(1_234L, "qbft-commit", true, "SECP256K1-(MLDSA44)");

    final String[] header = MetricWriters.buildVerifyHeader().trim().split(",", -1);
    assertThat(line).endsWith("qbft-commit\n");
    assertThat(line.trim().split(",", -1))
        .hasSameSizeAs(header)
        .containsExactly("1234", "yes", "SECP256K1-(MLDSA44)", "qbft-commit");
  }

  @Test
  void aSignatureThatFailsIsRecordedAsNotValid() {
    final String line = MetricWriters.verifyMetricsLine(1L, "discv4-packet", false, "MLDSA44");

    assertThat(line.trim().split(",", -1)[1]).isEqualTo("no");
  }

  @Test
  void aTimedVerificationReturnsTheResultOfTheCheck() {
    assertThat(MetricWriters.timeVerification("node-record", "MLDSA44", () -> true)).isTrue();
    assertThat(MetricWriters.timeVerification("node-record", "MLDSA44", () -> false)).isFalse();
  }

  @Test
  void aVerificationThatThrowsPassesTheExceptionOn() {
    assertThatThrownBy(
            () ->
                MetricWriters.timeVerification(
                    "tx",
                    "MLDSA44",
                    () -> {
                      throw new IllegalArgumentException("malformed key");
                    }))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("malformed key");
  }

  @Test
  void aPkrLineHasTheColumnsOfTheHeader() {
    final String line =
        MetricWriters.pkrMetricsLine(1_234L, "qbft-commit-seal", true, "(SECP256K1)-MLDSA44");

    final String[] header = MetricWriters.buildPkrHeader().trim().split(",", -1);
    assertThat(line).endsWith("\n");
    assertThat(line.trim().split(",", -1))
        .hasSameSizeAs(header)
        .containsExactly("1234", "yes", "(SECP256K1)-MLDSA44", "qbft-commit-seal");
  }

  @Test
  void aKeyThatCannotBeRecoveredIsRecordedAsNotRecovered() {
    final String line = MetricWriters.pkrMetricsLine(1L, "discv4-packet", false, "SECP256K1");

    assertThat(line.trim().split(",", -1)[1]).isEqualTo("no");
  }

  @Test
  void aTimedRecoveryReturnsWhatWasRecovered() {
    assertThat(MetricWriters.timeRecovery("discv4-packet", "SECP256K1", () -> Optional.of("key")))
        .contains("key");
    assertThat(MetricWriters.timeRecovery("discv4-packet", "SECP256K1", Optional::empty)).isEmpty();
  }

  @Test
  void aRecoveryThatThrowsPassesTheExceptionOn() {
    assertThatThrownBy(
            () ->
                MetricWriters.timeRecovery(
                    "rlpx-handshake",
                    "SECP256K1",
                    () -> {
                      throw new IllegalArgumentException("Invalid point compression");
                    }))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid point compression");
  }

  @Test
  void aVerifiedHybridNamesTheHalfThatWasVerified() {
    assertThat(MetricWriters.verifiedAlgorithm(dsa(DSAParametersSet.SECP256K1MLDSA44)))
        .isEqualTo("SECP256K1-(MLDSA44)");
    assertThat(MetricWriters.verifiedAlgorithm(dsa(DSAParametersSet.SECP256K1FALCON512)))
        .isEqualTo("SECP256K1-(FALCON512)");
  }

  @Test
  void aVerifiedSingleAlgorithmIsNamedAsItIs() {
    assertThat(MetricWriters.verifiedAlgorithm(dsa(DSAParametersSet.MLDSA44)))
        .isEqualTo("MLDSA44");
    assertThat(MetricWriters.verifiedAlgorithm(dsa(DSAParametersSet.FALCON512)))
        .isEqualTo("FALCON512");
  }

  @Test
  void aRecoveryNamesTheHalfWhoseKeyWasRecovered() {
    assertThat(
            MetricWriters.recoveredAlgorithm(
                DSAParametersSet.SECP256K1MLDSA44, DSAParametersSet.SECP256K1))
        .isEqualTo("(SECP256K1)-MLDSA44");
    assertThat(
            MetricWriters.recoveredAlgorithm(DSAParametersSet.SECP256K1, DSAParametersSet.SECP256K1))
        .isEqualTo("SECP256K1");
  }

  @Test
  void everyFileEndsWithTheAlgorithmAndTheContext() {
    assertThat(MetricWriters.buildSignHeader())
        .isEqualTo("DSASigningTime(ns),Algorithm,Context\n");
    assertThat(MetricWriters.buildVerifyHeader())
        .isEqualTo("DSAVerificationTime(ns),isSignatureValid,Algorithm,Context\n");
    assertThat(MetricWriters.buildPkrHeader())
        .isEqualTo("PKRTime(ns),isRecovered,Algorithm,Context\n");
  }

  private static DigitalSignatureAlgorithm dsa(
      final DSAParametersSet params) {
    return ALGORITHMS.getDSAByName(params.getName()).get();
  }
}
