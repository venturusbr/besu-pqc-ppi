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

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.SignatureAlgorithmType;

import java.util.Optional;

/**
 * How a node's algorithm relates to the network's elliptic curve, which the genesis file's {@code
 * ecCurve} sets in {@link SignatureAlgorithmFactory}, SECP256K1 when it is absent. Code that
 * predates {@code --node-dsa} -- the RLPx handshake, legacy transaction signatures, node keys read
 * by the security module -- uses that curve, so a node signing on another one would sign with one
 * curve and be verified with the other.
 *
 * <p>Shared by every command that picks a node algorithm, so a key generated for a network is the
 * key a node of that network then uses.
 */
public final class NodeDsaCurve {

  private NodeDsaCurve() {}

  /**
   * The node algorithm to use: the one given, and otherwise the network's curve. Must be called
   * once the curve has been set from the genesis file.
   *
   * @param nodeDsa the algorithm given with {@code --node-dsa}, or null when none was
   * @return the name of the node's algorithm
   */
  public static String nodeDsaOrNetworkCurve(final String nodeDsa) {
    if (nodeDsa != null) {
      return nodeDsa;
    }
    return SignatureAlgorithmFactory.getInstance().getDsaParametersSet().getName();
  }

  /**
   * Why a node algorithm cannot be used on the network's curve, if it cannot. Only its elliptic
   * curve, or a hybrid's classical half, can conflict; the default never does. Must be called once
   * the curve has been set from the genesis file.
   *
   * @param nodeDsa the node's algorithm
   * @return the reason, for the user, if the algorithm conflicts with the network's curve
   */
  public static Optional<String> conflictWithNetworkCurve(final DigitalSignatureAlgorithm nodeDsa) {
    final DigitalSignatureAlgorithm classical =
        nodeDsa instanceof HybridDigitalSignatureAlgorithm hybrid
            ? hybrid.getFirstAlgorithm()
            : nodeDsa;
    if (!(classical instanceof SignatureAlgorithm nodeCurve)) {
      return Optional.empty();
    }
    final SignatureAlgorithm networkCurve = SignatureAlgorithmFactory.getInstance();
    if (nodeCurve.getDsaParametersSet() == networkCurve.getDsaParametersSet()) {
      return Optional.empty();
    }

    final String nodeDsaName = nodeDsa.getDsaParametersSet().getName();
    final String network =
        String.format(
            "this network uses %s (the genesis file's ecCurve, %s when it is not set)",
            networkCurve.getCurveName(), SignatureAlgorithmType.DEFAULT_EC_CURVE_NAME);
    if (nodeDsa instanceof HybridDigitalSignatureAlgorithm) {
      // Hybrids pair their post-quantum half with secp256k1 only, for now.
      return Optional.of(
          String.format(
              "--node-dsa %s pairs its post-quantum half with %s, but %s. Hybrid algorithms are"
                  + " only available with %s for now: use --node-dsa %s, or leave it unset.",
              nodeDsaName,
              nodeCurve.getCurveName(),
              network,
              nodeCurve.getCurveName(),
              networkCurve.getDsaParametersSet().getName()));
    }
    return Optional.of(
        String.format(
            "--node-dsa %s signs on the %s curve, but %s. Use a --node-dsa on %s, or set"
                + " \"ecCurve\": \"%s\" in the genesis config.",
            nodeDsaName,
            nodeCurve.getCurveName(),
            network,
            networkCurve.getCurveName(),
            nodeCurve.getCurveName()));
  }
}
