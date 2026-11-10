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
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class LegacyCodeDelegationEncoder {
  public static void encodeAuthorizationDetails(
      final CodeDelegation payload, final RLPOutput rlpOutput) {
    rlpOutput.writeBigIntegerScalar(payload.chainId());
    rlpOutput.writeBytes(payload.address().getBytes().copy());
    rlpOutput.writeLongScalar(payload.nonce());
  }

  public static void encode(
      final CodeDelegation payload, final RLPOutput rlpOutput, final Boolean includeSignature) {
    rlpOutput.startList();
    encodeAuthorizationDetails(payload, rlpOutput);
    if (includeSignature) {
      SECPSignature secpSignature = (SECPSignature) payload.signature();
      rlpOutput.writeUnsignedByte(secpSignature.getRecId() & 0xFF);
      rlpOutput.writeBigIntegerScalar(secpSignature.getR());
      rlpOutput.writeBigIntegerScalar(secpSignature.getS());
    }
    rlpOutput.endList();
  }
}
