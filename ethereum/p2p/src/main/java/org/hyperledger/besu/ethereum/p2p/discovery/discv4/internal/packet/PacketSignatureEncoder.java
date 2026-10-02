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
package org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet;

import org.hyperledger.besu.crypto.signature.Signature;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.tuweni.bytes.Bytes;

// TODO: delete this class
@Singleton
public class PacketSignatureEncoder {

  public @Inject PacketSignatureEncoder() {}

  /**
   * The signature as it travels on the wire.
   *
   * <p>Each algorithm already knows its own encoding, so this defers to it rather than assuming
   * the 65-byte {@code r || s || v} of ECDSA: a hybrid signature is the concatenation of a
   * classical one and an ML-DSA-44 one, and truncating it would drop the half that matters.
   *
   * @param signature the signature to encode
   * @return its encoded bytes
   */
  public Bytes encodeSignature(final Signature signature) {
    return signature.encodedBytes();
  }
}
