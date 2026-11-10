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
package org.hyperledger.besu.crypto.providers;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;

public interface VerifierProvider {
  DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId);

  DSAParametersSet getActiveDsaParametersSet();

  Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk);

  List<String> getAccountsSupportedDSANames();

  /**
   * Whether accounts may sign with the network's curve, the genesis ecCurve. Standard transactions
   * and code delegations carry no DSA type and are signed with it, so they never go through {@link
   * #getAccountEnabledDSAById}.
   *
   * @return true if the network's curve is enabled for accounts
   */
  boolean isNetworkCurveEnabled();

  /**
   * Returns the {@link DigitalSignatureAlgorithm} this node is currently configured to use (e.g.
   * via the node's active DSA configuration), as opposed to a per-account/transaction DSA looked up
   * by id.
   *
   * @return the node's active digital signature algorithm
   */
  DigitalSignatureAlgorithm getActiveDSA();
}
