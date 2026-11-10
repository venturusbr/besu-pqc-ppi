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

public class CompositeSignature implements Signature {
  private final Signature firstSignature;
  private final Signature secondSignature;

  private CompositeSignature(final Signature firstSignature, final Signature secondSignature) {
    this.firstSignature = firstSignature;
    this.secondSignature = secondSignature;
  }

  public Signature getFirstSignature() {
    return firstSignature;
  }

  public Signature getSecondSignature() {
    return secondSignature;
  }

  @Override
  public String getAlgorithm() {
    return firstSignature.getAlgorithm() + "-" + secondSignature.getAlgorithm();
  }

  @Override
  public Boolean isValid(final SignatureValidationContext context) {
    return firstSignature.isValid(context) && secondSignature.isValid(context);
  }

  @Override
  public Bytes encodedBytes() {
    return Bytes.concatenate(
        Bytes.wrap(firstSignature.encodedBytes()), Bytes.wrap(secondSignature.encodedBytes()));
  }

  public static CompositeSignature create(
      final Signature firstSignature, final Signature secondSignature) {
    return new CompositeSignature(firstSignature, secondSignature);
  }
}
