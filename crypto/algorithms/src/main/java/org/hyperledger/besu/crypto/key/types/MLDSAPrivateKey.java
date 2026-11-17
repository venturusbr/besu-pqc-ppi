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

import static com.google.common.base.Preconditions.checkArgument;

import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

public class MLDSAPrivateKey implements PrivateKey {
  private final DSAParametersSet parametersSet;
  private final Bytes encoded;
  private final String format;

  private MLDSAPrivateKey(
      final DSAParametersSet parametersSet, final Bytes encoded, final String format) {
    this.parametersSet = parametersSet;
    this.format = format;
    this.encoded = encoded;
  }

  /**
   * Gets the parameter set this key belongs to.
   *
   * @return the parameter set
   */
  public DSAParametersSet getParametersSet() {
    return parametersSet;
  }

  @Override
  public String getAlgorithm() {
    return parametersSet.getName();
  }

  @Override
  public String getFormat() {
    return format;
  }

  @Override
  public byte[] getEncoded() {
    return encoded.toArrayUnsafe();
  }

  /**
   * Creates a key from either the 32-byte seed (FIPS 204 xi), which is expanded, or the expanded
   * private key itself. Any other length is refused here, as {@link FalconPrivateKey#create} does,
   * instead of failing later inside BouncyCastle when the public key is derived or data is signed.
   *
   * @throws IllegalArgumentException if {@code skBytes} is neither the seed nor the expanded length
   */
  public static MLDSAPrivateKey create(
      final Bytes skBytes, final DSAParametersSet dsaParametersSet) {
    checkArgument(
        skBytes.size() == dsaParametersSet.getSeedLength()
            || skBytes.size() == dsaParametersSet.getPrivateKeyLength(),
        "%s private key must be %s bytes, or a %s-byte seed, got %s",
        dsaParametersSet.getName(),
        dsaParametersSet.getPrivateKeyLength(),
        dsaParametersSet.getSeedLength(),
        skBytes.size());
    if (skBytes.size() == dsaParametersSet.getSeedLength()) {
      return createFromSeed(skBytes.toArrayUnsafe(), dsaParametersSet);
    }
    return new MLDSAPrivateKey(dsaParametersSet, skBytes, "RAW");
  }

  private static MLDSAPrivateKey createFromSeed(
      final byte[] seed, final DSAParametersSet dsaParametersSet) {
    MLDSAParameters mldsaParams =
        MLDSA.getBCMLDSAParametersByDSAParameterName(dsaParametersSet.getName());
    MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(mldsaParams, seed);
    return new MLDSAPrivateKey(dsaParametersSet, Bytes.wrap(skParams.getEncoded()), "RAW");
  }
}
