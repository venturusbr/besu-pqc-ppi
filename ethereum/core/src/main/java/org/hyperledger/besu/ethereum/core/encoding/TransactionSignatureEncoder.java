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
package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import org.apache.tuweni.bytes.Bytes;

public class TransactionSignatureEncoder {

  public static void writeSignatureBytes(final Signature signature, final RLPOutput out) {
    Bytes signatureBytes = signature.encodedBytes();
    out.writeBytes(signatureBytes);
  }

  public static void writeSignatureAndV(final Transaction transaction, final RLPOutput out) {
    SECPSignature secpSignature = (SECPSignature) transaction.getSignature();
    out.writeBigIntegerScalar(transaction.getV());
    writeStandardSignature(secpSignature, out);
  }

  public static void writeStandardSignatureAndRecoveryId(
      final Signature signature, final RLPOutput out) {
    SECPSignature secpSignature = (SECPSignature) signature;
    out.writeIntScalar(secpSignature.getRecId());
    writeStandardSignature(secpSignature, out);
  }

  private static void writeStandardSignature(
      final SECPSignature secpSignature, final RLPOutput out) {
    out.writeBigIntegerScalar(secpSignature.getR());
    out.writeBigIntegerScalar(secpSignature.getS());
  }
}
