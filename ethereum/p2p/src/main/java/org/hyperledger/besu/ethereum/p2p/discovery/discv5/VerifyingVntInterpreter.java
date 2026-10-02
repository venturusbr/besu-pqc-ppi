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
package org.hyperledger.besu.ethereum.p2p.discovery.discv5;

import org.hyperledger.besu.ethereum.p2p.discovery.EnrSignatureValidator;

import org.ethereum.beacon.discovery.schema.IdentitySchemaV4Interpreter;
import org.ethereum.beacon.discovery.schema.IdentitySchemaVntInterpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;

/**
 * The library's {@code vnt} interpreter, with the hybrid signature check it leaves to Besu.
 *
 * <p>The discovery library has no ML-DSA-44 implementation, so its {@code vnt} interpreter only
 * checks that a record is well formed. The library still calls {@link NodeRecord#isValid()} on
 * every record it receives, in handshakes and in NODES responses, so verifying the signature here
 * keeps forged records out of the routing table without touching the library.
 */
class VerifyingVntInterpreter extends IdentitySchemaVntInterpreter {

  private final EnrSignatureValidator enrSignatureValidator;

  VerifyingVntInterpreter(final EnrSignatureValidator enrSignatureValidator) {
    this.enrSignatureValidator = enrSignatureValidator;
  }

  /**
   * A record factory that decodes {@code v4} records as the library does and verifies {@code vnt}
   * records with {@link EnrSignatureValidator}.
   *
   * @return the factory to hand to the discovery system
   */
  static NodeRecordFactory nodeRecordFactory() {
    return new NodeRecordFactory(
        new IdentitySchemaV4Interpreter(),
        new VerifyingVntInterpreter(new EnrSignatureValidator()));
  }

  @Override
  public boolean isValid(final NodeRecord nodeRecord) {
    return super.isValid(nodeRecord) && enrSignatureValidator.isValid(nodeRecord);
  }
}
