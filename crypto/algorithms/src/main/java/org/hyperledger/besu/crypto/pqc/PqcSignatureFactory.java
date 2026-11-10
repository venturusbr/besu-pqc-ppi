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
package org.hyperledger.besu.crypto.pqc;

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.CrystalsDilithiumSignature;
import org.hyperledger.besu.crypto.pqc.falcon.FalconSignature;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlusSignature;

import java.security.PrivateKey;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableMap;

public class PqcSignatureFactory {
  private static final ImmutableMap<String, Supplier<PqcSignature>>
      PQC_SUPPORTED_SIGNATURE_ALGORITHMS =
          ImmutableMap.of(
              "Dilithium",
              CrystalsDilithiumSignature::new,
              "SPHINCSPlus",
              SphincsPlusSignature::new,
              "Falcon",
              FalconSignature::new);

  public static PqcSignature createSignature(
      final PrivateKey privateKey, final byte[] dataToSign, final String algorithmName) {
    PqcSignature pqcSignature = PQC_SUPPORTED_SIGNATURE_ALGORITHMS.get(algorithmName).get();
    pqcSignature.create(dataToSign, privateKey);
    return pqcSignature;
  }
}
