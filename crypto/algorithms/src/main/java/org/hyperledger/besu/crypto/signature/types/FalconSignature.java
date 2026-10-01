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
package org.hyperledger.besu.crypto.signature.types;

import org.hyperledger.besu.crypto.SignatureValidationContext;
import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

import org.apache.tuweni.bytes.Bytes;

/**
 * A Falcon signature.
 *
 * <p>Unlike ML-DSA, Falcon signatures are variable-length: the compressed encoding depends on the
 * signed message and the per-signature nonce. Their length is therefore carried by the enclosing
 * RLP item rather than implied by the algorithm, which is why a Falcon {@link DSAParametersSet}
 * declares no fixed signature length.
 */
public final class FalconSignature implements Signature {
  private final DSAParametersSet parametersSet;
  private final Bytes encodedBytes;

  private FalconSignature(final DSAParametersSet parametersSet, final Bytes encodedBytes) {
    this.parametersSet = parametersSet;
    this.encodedBytes = encodedBytes;
  }

  /**
   * Wraps an encoded signature.
   *
   * @param encodedBytes the signature as produced by BouncyCastle's {@code FalconSigner}
   * @param parametersSet the Falcon parameter set it was produced with
   * @return the signature
   * @throws IllegalArgumentException if {@code parametersSet} is not a Falcon parameter set
   */
  public static FalconSignature create(
      final Bytes encodedBytes, final DSAParametersSet parametersSet) {
    Falcon.parametersFor(parametersSet);
    return new FalconSignature(parametersSet, encodedBytes.copy());
  }

  /**
   * Largest signature accepted as structurally valid for a parameter set, in bytes. The reasoning
   * behind each value is documented with that parameter set in {@link Falcon}.
   *
   * @param parametersSet a Falcon parameter set
   * @return its maximum signature length
   */
  public static int maxLength(final DSAParametersSet parametersSet) {
    return Falcon.parametersFor(parametersSet).maxSignatureLength();
  }

  /**
   * Gets the parameter set this signature was produced with.
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
  public Bytes encodedBytes() {
    return encodedBytes;
  }

  /**
   * Structural check only: the signature is non-empty and no longer than {@link
   * #maxLength(DSAParametersSet)}. Whether it is genuine is decided by verification.
   */
  @Override
  public Boolean isValid(final SignatureValidationContext context) {
    return !encodedBytes.isEmpty() && encodedBytes.size() <= maxLength(parametersSet);
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    return o instanceof FalconSignature that
        && parametersSet == that.parametersSet
        && encodedBytes.equals(that.encodedBytes);
  }

  @Override
  public int hashCode() {
    return 31 * parametersSet.hashCode() + encodedBytes.hashCode();
  }

  @Override
  public String toString() {
    return "FalconSignature{" + parametersSet.getName() + ", " + encodedBytes.toHexString() + "}";
  }
}
