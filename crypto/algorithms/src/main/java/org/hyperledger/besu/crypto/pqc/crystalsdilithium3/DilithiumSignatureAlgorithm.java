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

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface DilithiumSignatureAlgorithm {
  public Dilithium3KeyPair generateKeyPair();

  public Dilithium3KeyPair createDilithium3KeyPair(
      Dilithium3PrivateKey privateKey, Dilithium3PublicKey publicKey);

  public CrystalsDilithiumSignature sign(byte[] secpSignatureEncoded, PrivateKey privateKeyPQC);

  public boolean verify(PublicKey publicKey, byte[] dataToSign, byte[] signature);

  public Dilithium3PrivateKey createPrivateKey(String hex);

  public Dilithium3PublicKey createPublicKey(String hex);
}
