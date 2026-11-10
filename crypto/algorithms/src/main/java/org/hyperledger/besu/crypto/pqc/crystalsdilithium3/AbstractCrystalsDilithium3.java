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
package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public abstract class AbstractCrystalsDilithium3 extends PqcSignatureAlgorithm {

  private final DilithiumParameterSpec[] DILITHIUM_PARAMETER_SPEC = {
    DilithiumParameterSpec.dilithium2,
    DilithiumParameterSpec.dilithium3,
    DilithiumParameterSpec.dilithium5
  };

  protected KeyPairGenerator keyPairGenerator;

  public Dilithium3KeyPair generateKeyPair() {
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("Dilithium");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }

    DilithiumParameterSpec parameter =
        DILITHIUM_PARAMETER_SPEC[SignatureAlgorithmFactory.getPqcParameterSpecIndex()];

    Dilithium3KeyPair keyPair =
        Dilithium3KeyPair.generateCrystalsDilithiumPair(keyPairGenerator, parameter);

    return keyPair;
  }

  public Dilithium3KeyPair createDilithium3KeyPair(
      final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey) {
    return Dilithium3KeyPair.createKeyPair(privateKey, publicKey);
  }

  public Dilithium3PrivateKey createPrivateKey(final String hex) {
    byte[] encoded = Dilithium3PrivateKey.hexToBytes(hex);
    return Dilithium3PrivateKey.create(encoded);
  }

  public Dilithium3PublicKey createPublicKey(final String hex) {
    byte[] encoded = Dilithium3PublicKey.hexToBytes(hex);
    return Dilithium3PublicKey.create(encoded);
  }
}
