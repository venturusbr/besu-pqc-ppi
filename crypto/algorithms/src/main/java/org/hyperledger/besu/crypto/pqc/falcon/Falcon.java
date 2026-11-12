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
package org.hyperledger.besu.crypto.pqc.falcon;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconKeyPair;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPrivateKey;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPublicKey;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class Falcon extends PqcSignatureAlgorithm {

  protected KeyPairGenerator keyPairGenerator;

  private final FalconParameterSpec[] FALCON_PARAMETER_SPECS = {
    FalconParameterSpec.falcon_512, FalconParameterSpec.falcon_1024
  };

  public FalconKeyPair generateKeyPair() {
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("Falcon");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
    FalconParameterSpec parameter =
        FALCON_PARAMETER_SPECS[SignatureAlgorithmFactory.getPqcParameterSpecIndex()];

    FalconKeyPair keyPair = FalconKeyPair.generate(keyPairGenerator, parameter);

    return keyPair;
  }

  public FalconKeyPair createFalconKeyPair(
      final FalconPrivateKey privateKey, final FalconPublicKey publicKey) {
    return FalconKeyPair.createKeyPair(privateKey, publicKey);
  }

  public FalconPrivateKey createPrivateKey(final String hex) {
    byte[] encoded = FalconPrivateKey.hexToBytes(hex);
    return FalconPrivateKey.create(encoded);
  }

  public FalconPublicKey createPublicKey(final String hex) {
    byte[] encoded = FalconPublicKey.hexToBytes(hex);
    return FalconPublicKey.create(encoded);
  }

  @Override
  public String getAlgorithmName() {
    return "Falcon";
  }

  @Override
  public String formatAlgorithmAndParameterTitle() {
    String parameterName =
        switch (SignatureAlgorithmFactory.getPqcParameterSpecIndex()) {
          case 0 -> "_512";
          case 1 -> "_1024";
          default -> "_512";
        };
    return getAlgorithmName() + parameterName;
  }
}
