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
package org.hyperledger.besu.consensus.common.bft.inttest;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.SignatureAlgorithmType;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;

import java.security.InvalidAlgorithmParameterException;
import java.util.Optional;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Runs consensus integration tests under the signature algorithm named by the {@value
 * #DSA_PROPERTY} system property, such as {@code MLDSA44}, {@code SECP256K1-MLDSA44} or {@code
 * SECP256R1}. Without the property the tests run under the default algorithm, SECP256K1, as before.
 *
 * <p>Registered through JUnit's extension auto-detection, so every test class in a suite runs under
 * the chosen algorithm without being changed. Node keys follow it through {@code
 * NodeKeyUtils.generate()}.
 */
public class ActiveDsaExtension implements BeforeAllCallback, AfterAllCallback {

  /** The system property naming the algorithm to run under. */
  public static final String DSA_PROPERTY = "besu.consensus.test.dsa";

  /**
   * The algorithm the tests run under, if one was requested.
   *
   * @return the algorithm name, as accepted by {@code --node-dsa}
   */
  public static Optional<String> requestedDsa() {
    return Optional.ofNullable(System.getProperty(DSA_PROPERTY)).filter(name -> !name.isBlank());
  }

  @Override
  public void beforeAll(final ExtensionContext context) throws InvalidAlgorithmParameterException {
    final Optional<String> dsa = requestedDsa();
    if (dsa.isPresent()) {
      final DigitalSignatureAlgorithmConfiguration config =
          new DigitalSignatureAlgorithmConfiguration();
      config.setNodeActiveDSA(dsa.get());
      DSAProviderFactory.setDsaProvider(config, null);
      // A node on SECP256R1 runs on a network whose genesis sets that curve, as Besu refuses to
      // start otherwise; code that predates --node-dsa reads the curve from here.
      if (dsa.get().equals(DSAParametersSet.SECP256R1.getName())) {
        SignatureAlgorithmFactory.resetInstance();
        SignatureAlgorithmFactory.setInstance(
            SignatureAlgorithmType.create(SignatureAlgorithmType.SECP_256_R1_CURVE_NAME));
      }
    }
  }

  @Override
  public void afterAll(final ExtensionContext context) {
    if (requestedDsa().isPresent()) {
      DSAProviderFactory.resetDsaProvider();
      SignatureAlgorithmFactory.resetInstance();
    }
  }
}
