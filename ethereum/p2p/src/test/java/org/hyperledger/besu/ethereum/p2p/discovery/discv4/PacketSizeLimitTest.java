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
package org.hyperledger.besu.ethereum.p2p.discovery.discv4;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import org.junit.jupiter.api.Test;

/**
 * The packet limit has to hold a record of the hybrid vnt scheme, which is far past the 1280 bytes
 * the devp2p specification allows.
 */
class PacketSizeLimitTest {

  @Test
  void theLimitHoldsAHybridKeyAndSignature() {
    // a vnt record is dominated by these two, and still needs room for the transport fields
    final int hybridKeyAndSignature =
        DSAParametersSet.SECP256K1MLDSA44.getPublicKeyLength()
            + DSAParametersSet.SECP256K1MLDSA44.getSignatureLength();

    assertThat(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES).isGreaterThan(hybridKeyAndSignature);
  }

  @Test
  void theLimitMatchesTheDiscoveryLibrary() {
    // both carry the same records, so a packet one side accepts the other must not truncate
    assertThat(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES)
        .isEqualTo(
            org.ethereum.beacon.discovery.pipeline.handler.IncomingDataPacker.MAX_PACKET_SIZE);
  }
}
