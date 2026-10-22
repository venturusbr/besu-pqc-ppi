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
package org.hyperledger.besu.cli.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.SignatureAlgorithmType;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NodeDsaCurveTest {

  @AfterEach
  void resetCurve() {
    SignatureAlgorithmFactory.resetInstance();
  }

  private static void networkOn(final String ecCurve) {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(SignatureAlgorithmType.create(ecCurve));
  }

  private static DigitalSignatureAlgorithm dsa(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }

  @Test
  void aGivenNodeDsaIsKept() {
    networkOn("secp256r1");

    assertThat(NodeDsaCurve.nodeDsaOrNetworkCurve("MLDSA44")).isEqualTo("MLDSA44");
  }

  @Test
  void withoutANodeDsaTheNetworksCurveIsUsed() {
    networkOn("secp256r1");
    assertThat(NodeDsaCurve.nodeDsaOrNetworkCurve(null)).isEqualTo("SECP256R1");

    networkOn("secp256k1");
    assertThat(NodeDsaCurve.nodeDsaOrNetworkCurve(null)).isEqualTo("SECP256K1");
  }

  @Test
  void withoutAnEcCurveTheNetworkIsOnSecp256k1() {
    assertThat(NodeDsaCurve.nodeDsaOrNetworkCurve(null)).isEqualTo("SECP256K1");
  }

  @Test
  void algorithmsOnTheNetworksCurveDoNotConflict() {
    networkOn("secp256r1");
    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.SECP256R1))).isEmpty();

    networkOn("secp256k1");
    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.SECP256K1))).isEmpty();
    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.SECP256K1MLDSA44)))
        .isEmpty();
  }

  @Test
  void anAlgorithmWithoutACurveDoesNotConflict() {
    networkOn("secp256r1");

    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.MLDSA44))).isEmpty();
  }

  @Test
  void anotherCurveConflicts() {
    networkOn("secp256r1");

    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.SECP256K1)))
        .contains(
            "--node-dsa SECP256K1 signs on the secp256k1 curve, but this network uses secp256r1"
                + " (the genesis file's ecCurve, secp256k1 when it is not set). Use a --node-dsa"
                + " on secp256r1, or set \"ecCurve\": \"secp256k1\" in the genesis config.");
  }

  @Test
  void aHybridOnAnotherCurveIsReportedAsNotYetAvailable() {
    networkOn("secp256r1");

    assertThat(NodeDsaCurve.conflictWithNetworkCurve(dsa(DSAParametersSet.SECP256K1FALCON512)))
        .contains(
            "--node-dsa SECP256K1-FALCON512 pairs its post-quantum half with secp256k1, but this"
                + " network uses secp256r1 (the genesis file's ecCurve, secp256k1 when it is not"
                + " set). Hybrid algorithms are only available with secp256k1 for now: use"
                + " --node-dsa SECP256R1, or leave it unset.");
  }
}
