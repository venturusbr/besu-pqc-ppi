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
package org.hyperledger.besu.crypto;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.util.function.Supplier;

import com.google.common.base.Suppliers;

/**
 * The elliptic-curve algorithm for a given curve.
 *
 * <p>{@link SignatureAlgorithmFactory} holds a single, process-wide instance: the curve the network
 * was configured with. Keys and signatures that name their curve -- an account signing with a
 * different curve than the node, say -- must be handled by that curve's algorithm instead, or a
 * SECP256R1 key would be read as a SECP256K1 one.
 */
public final class SECPCurves {

  private static final Supplier<SignatureAlgorithm> SECP256K1_INSTANCE =
      Suppliers.memoize(SECP256K1::new);
  private static final Supplier<SignatureAlgorithm> SECP256R1_INSTANCE =
      Suppliers.memoize(SECP256R1::new);

  private SECPCurves() {}

  /**
   * The algorithm for a curve. When the curve is the one {@link SignatureAlgorithmFactory} was
   * configured with, its instance is returned, so settings applied to it at startup (such as
   * disabling the native library) still hold.
   *
   * @param curve SECP256K1 or SECP256R1
   * @return the algorithm for that curve
   * @throws IllegalArgumentException if the parameters set is not an elliptic curve
   */
  public static SignatureAlgorithm of(final DSAParametersSet curve) {
    if (SignatureAlgorithmFactory.isInstanceSet()) {
      final SignatureAlgorithm configured = SignatureAlgorithmFactory.getInstance();
      if (configured.getDsaParametersSet() == curve) {
        return configured;
      }
    }
    return switch (curve) {
      case SECP256K1 -> SECP256K1_INSTANCE.get();
      case SECP256R1 -> SECP256R1_INSTANCE.get();
      default -> throw new IllegalArgumentException(curve.getName() + " is not an elliptic curve");
    };
  }
}
