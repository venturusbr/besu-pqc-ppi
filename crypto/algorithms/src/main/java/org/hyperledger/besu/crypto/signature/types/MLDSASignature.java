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
package org.hyperledger.besu.crypto.signature.types;

import org.hyperledger.besu.crypto.SignatureValidationContext;
import org.hyperledger.besu.crypto.signature.Signature;

import org.apache.tuweni.bytes.Bytes;

public class MLDSASignature implements Signature {
  private final Bytes encodedBytes;
  private final String algorithmName;

  private MLDSASignature(final String algorithmName, final Bytes encodedBytes) {
    this.algorithmName = algorithmName;
    this.encodedBytes = encodedBytes;
  }

  @Override
  public String getAlgorithm() {
    return algorithmName;
  }

  @Override
  public Bytes encodedBytes() {
    return encodedBytes;
  }

  @Override
  public Boolean isValid(final SignatureValidationContext context) {
    return encodedBytes != null && !encodedBytes.isEmpty();
  }

  public static MLDSASignature create(final String algorithmName, final Bytes encodedBytes) {
    return new MLDSASignature(algorithmName, encodedBytes);
  }
}
