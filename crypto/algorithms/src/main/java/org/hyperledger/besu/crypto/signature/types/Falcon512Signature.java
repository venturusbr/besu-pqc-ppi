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
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

import org.apache.tuweni.bytes.Bytes;

/**
 * A Falcon-512 signature.
 *
 * <p>Unlike ML-DSA, Falcon signatures are variable-length: the compressed encoding depends on the
 * signed message and the per-signature nonce. Their length is therefore carried by the enclosing
 * RLP item rather than implied by the algorithm, which is why {@link DSAParametersSet#FALCON512}
 * declares no fixed signature length.
 */
public final class Falcon512Signature implements Signature {

  /**
   * Largest signature accepted as structurally valid, in bytes.
   *
   * <p>752 is the maximum Falcon-512 signature size used by liboqs. It was chosen over the smaller
   * bound BouncyCastle applies internally ({@code CRYPTO_BYTES = 690} in {@code FalconNIST}),
   * because BouncyCastle uses 690 only to size its own signing buffer and does not enforce it when
   * verifying: its verifier checks the header byte and then decodes, whatever the length. A
   * transaction may be signed by a client using another implementation, so capping at 690 could
   * reject a signature that would still verify. 752 never rejects a signature either library
   * considers well-sized.
   *
   * <p>The cap exists to reject oversized input before any decoding work, not to decide validity:
   * anything longer cannot verify anyway, since BouncyCastle's decoder rejects even a single
   * trailing byte. Signatures observed from BouncyCastle range from 648 to 662 bytes.
   *
   * <p>This is also why signatures are not padded to a fixed length: BouncyCastle rejects Falcon's
   * zero-padded format, so they are carried at their natural, variable length.
   */
  public static final int MAX_LENGTH = 752;

  private final Bytes encodedBytes;

  private Falcon512Signature(final Bytes encodedBytes) {
    this.encodedBytes = encodedBytes;
  }

  /**
   * Wraps an encoded signature.
   *
   * @param encodedBytes the signature as produced by BouncyCastle's {@code FalconSigner}
   * @return the signature
   */
  public static Falcon512Signature create(final Bytes encodedBytes) {
    return new Falcon512Signature(encodedBytes.copy());
  }

  @Override
  public String getAlgorithm() {
    return DSAParametersSet.FALCON512.getName();
  }

  @Override
  public Bytes encodedBytes() {
    return encodedBytes;
  }

  /**
   * Structural check only: the signature is non-empty and no longer than {@link #MAX_LENGTH}.
   * Whether it is genuine is decided by verification.
   */
  @Override
  public Boolean isValid(final SignatureValidationContext context) {
    return !encodedBytes.isEmpty() && encodedBytes.size() <= MAX_LENGTH;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    return o instanceof Falcon512Signature that && encodedBytes.equals(that.encodedBytes);
  }

  @Override
  public int hashCode() {
    return encodedBytes.hashCode();
  }

  @Override
  public String toString() {
    return "Falcon512Signature{" + encodedBytes.toHexString() + "}";
  }
}
