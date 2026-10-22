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
package org.hyperledger.besu.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;

import java.io.IOException;
import java.nio.file.Path;

import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A node's --node-dsa must sign on the network's elliptic curve, which the genesis file's ecCurve
 * sets. Without --node-dsa the node uses that curve; an explicit --node-dsa on another curve is
 * refused, and Besu says why.
 */
class NodeDsaEcCurveTest extends CommandTestAbstract {

  // Only the curve check's error is asserted on: other startup output depends on the platform,
  // such as a missing native library on Windows.
  private static final String CURVE_ERROR = "this network uses";

  private static final JsonObject SECP256R1_GENESIS =
      new JsonObject().put("config", new JsonObject().put("ecCurve", "secp256r1"));

  @BeforeEach
  void resetCurve() {
    SignatureAlgorithmFactory.resetInstance();
    DSAProviderFactory.resetDsaProvider();
  }

  @AfterEach
  void resetCurveAgain() {
    resetCurve();
  }

  @Test
  void secp256r1NetworkNeedsNoNodeDsa() throws IOException {
    parseCommand("--genesis-file", secp256r1Genesis().toString());

    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(CURVE_ERROR);
    assertThat(DSAProviderFactory.getActiveDsaParametersSet())
        .isEqualTo(DSAParametersSet.SECP256R1);
    assertThat(SignatureAlgorithmFactory.getInstance().getDsaParametersSet())
        .isEqualTo(DSAParametersSet.SECP256R1);
  }

  @Test
  void withoutEcCurveTheNodeStaysOnSecp256k1() {
    parseCommand();

    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(CURVE_ERROR);
    assertThat(DSAProviderFactory.getActiveDsaParametersSet())
        .isEqualTo(DSAParametersSet.SECP256K1);
  }

  @Test
  void secp256r1NodeOnASecp256r1NetworkStarts() throws IOException {
    parseCommand("--genesis-file", secp256r1Genesis().toString(), "--node-dsa", "SECP256R1");

    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(CURVE_ERROR);
    assertThat(DSAProviderFactory.getActiveDsaParametersSet())
        .isEqualTo(DSAParametersSet.SECP256R1);
  }

  @Test
  void secp256k1NodeOnASecp256r1NetworkIsRefused() throws IOException {
    parseCommand("--genesis-file", secp256r1Genesis().toString(), "--node-dsa", "SECP256K1");

    assertThat(commandErrorOutput.toString(UTF_8))
        .contains(
            "--node-dsa SECP256K1 signs on the secp256k1 curve, but this network uses secp256r1"
                + " (the genesis file's ecCurve, secp256k1 when it is not set). Use a --node-dsa"
                + " on secp256r1, or set \"ecCurve\": \"secp256k1\" in the genesis config.");
  }

  @Test
  void secp256r1NodeWithoutEcCurveIsRefused() {
    parseCommand("--node-dsa", "SECP256R1");

    assertThat(commandErrorOutput.toString(UTF_8))
        .contains(
            "--node-dsa SECP256R1 signs on the secp256r1 curve, but this network uses secp256k1");
  }

  @Test
  void hybridOnASecp256r1NetworkIsRefusedAsNotYetAvailable() throws IOException {
    parseCommand(
        "--genesis-file", secp256r1Genesis().toString(), "--node-dsa", "SECP256K1-MLDSA44");

    assertThat(commandErrorOutput.toString(UTF_8))
        .contains(
            "--node-dsa SECP256K1-MLDSA44 pairs its post-quantum half with secp256k1, but this"
                + " network uses secp256r1 (the genesis file's ecCurve, secp256k1 when it is not"
                + " set). Hybrid algorithms are only available with secp256k1 for now: use"
                + " --node-dsa SECP256R1, or leave it unset.");
  }

  /**
   * The curve check only concerns algorithms with a curve. This does not mean such a node works on
   * a network: the RLPx handshake needs an elliptic-curve node key, or a hybrid with one, so a
   * purely post-quantum node cannot connect to peers on any network.
   */
  @Test
  void curveCheckDoesNotApplyToAPurelyPostQuantumAlgorithm() throws IOException {
    parseCommand("--genesis-file", secp256r1Genesis().toString(), "--node-dsa", "MLDSA44");

    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(CURVE_ERROR);
    assertThat(DSAProviderFactory.getActiveDsaParametersSet()).isEqualTo(DSAParametersSet.MLDSA44);
  }

  @Test
  void secp256k1NodeWithoutEcCurveStillStarts() {
    parseCommand("--node-dsa", "SECP256K1");

    assertThat(DSAProviderFactory.getActiveDsaParametersSet())
        .isEqualTo(DSAParametersSet.SECP256K1);
    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(CURVE_ERROR);
  }

  private Path secp256r1Genesis() throws IOException {
    return createFakeGenesisFile(SECP256R1_GENESIS);
  }
}
