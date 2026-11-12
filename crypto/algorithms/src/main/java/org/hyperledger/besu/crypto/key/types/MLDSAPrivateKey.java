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
package org.hyperledger.besu.crypto.key.types;

import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

public class MLDSAPrivateKey implements PrivateKey {
  private final String algorithmName;
  private final Bytes encoded;
  private final String format;

  private MLDSAPrivateKey(final String algorithmName, final Bytes encoded, final String format) {
    this.algorithmName = algorithmName;
    this.format = format;
    this.encoded = encoded;
  }

  @Override
  public String getAlgorithm() {
    return algorithmName;
  }

  @Override
  public String getFormat() {
    return format;
  }

  @Override
  public byte[] getEncoded() {
    return encoded.toArrayUnsafe();
  }

  public static MLDSAPrivateKey create(
      final Bytes skBytes, final DSAParametersSet dsaParametersSet) {
    if (skBytes.size() == dsaParametersSet.getSeedLength()) {
      return createFromSeed(skBytes.toArrayUnsafe(), dsaParametersSet);
    }
    return new MLDSAPrivateKey(dsaParametersSet.getName(), skBytes, "RAW");
  }

  private static MLDSAPrivateKey createFromSeed(
      final byte[] seed, final DSAParametersSet dsaParametersSet) {
    MLDSAParameters mldsaParams =
        MLDSA.getBCMLDSAParametersByDSAParameterName(dsaParametersSet.getName());
    MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(mldsaParams, seed);
    return new MLDSAPrivateKey(
        dsaParametersSet.getName(), Bytes.wrap(skParams.getEncoded()), "RAW");
  }
}
