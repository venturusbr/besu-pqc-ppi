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
package org.hyperledger.besu.ethereum.p2p.rlpx.wire;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.datatypes.Address;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class PeerInfoTest {

  @Test
  public void toStringIsSanitized() {
    final PeerInfo maliciousPeer =
        new PeerInfo(
            1,
            "ab\nc",
            List.of(Capability.create("c\ba\rp", 4)),
            30303,
            Bytes.fromHexStringLenient("0x1234"));

    final String toString = maliciousPeer.toString();

    assertThat(toString).doesNotContain(List.of("\n", "\b", "\r"));
  }

  /**
   * A hybrid node id is the 1376-byte composite key. Deriving the address used to go through a
   * SECPPublicKey, which only accepts 64 bytes, so it threw for every hybrid peer: consensus then
   * dropped every incoming message and never registered a validator connection.
   */
  @Test
  public void aHybridNodeIdYieldsTheAddressOfItsWholeKey() throws Exception {
    final KeyPair keyPair =
        new SupportedAlgorithms()
            .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
            .get()
            .generateNodeKeyPair();
    final Bytes nodeId = Bytes.wrap(keyPair.getPublicKey().getEncoded());

    final PeerInfo peerInfo = new PeerInfo(5, "besu", List.of(), 30303, nodeId);

    assertThat(nodeId.size()).isEqualTo(DSAParametersSet.SECP256K1MLDSA44.getPublicKeyLength());
    assertThat(peerInfo.getAddress()).isEqualTo(Address.extract(keyPair.getPublicKey()));
  }

  @Test
  public void aClassicalNodeIdKeepsItsAddress() {
    final KeyPair keyPair = SignatureAlgorithmFactory.getInstance().generateKeyPair();
    final Bytes nodeId = Bytes.wrap(keyPair.getPublicKey().getEncoded());

    final PeerInfo peerInfo = new PeerInfo(5, "besu", List.of(), 30303, nodeId);

    assertThat(peerInfo.getAddress()).isEqualTo(Address.extract(keyPair.getPublicKey()));
  }
}
