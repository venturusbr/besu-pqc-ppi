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
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DsaNotEnabledException;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;

/**
 * What a node verifies with before any DSA configuration is set, as in unit tests, the evmtool and
 * the reference tests, which never call {@link DSAProviderFactory#setDsaProvider}. It behaves as
 * upstream Besu: the network's curve signs standard transactions, and no DSA type is enabled for
 * flexible ones, not even the curve's.
 */
final class UnconfiguredVerifierProvider implements VerifierProvider {

  @Override
  public DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId) {
    throw new DsaNotEnabledException(dsaId);
  }

  @Override
  public DSAParametersSet getActiveDsaParametersSet() {
    return getActiveDSA().getDsaParametersSet();
  }

  @Override
  public Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk) {
    return getActiveDSA().verify(data, signature, pk);
  }

  @Override
  public List<String> getAccountsSupportedDSANames() {
    return List.of();
  }

  @Override
  public boolean isNetworkCurveEnabled() {
    return true;
  }

  @Override
  public DigitalSignatureAlgorithm getActiveDSA() {
    return SignatureAlgorithmFactory.getInstance();
  }
}
