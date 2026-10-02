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
package org.hyperledger.besu.ethereum.p2p.discovery.dns;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;

import java.net.InetAddress;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class EthereumNodeRecordTest {

  @ParameterizedTest
  @MethodSource("validEnrNodes")
  void enrIsParsed(
      final String enr,
      final Bytes expectedPublicKey,
      final InetAddress expectedIp,
      final int expectedTcpPort,
      final int expectedUdpPort) {
    final EthereumNodeRecord record = EthereumNodeRecord.fromEnr(enr);
    assertThat(record.publicKey()).isEqualTo(expectedPublicKey);
    assertThat(record.ip()).isEqualTo(expectedIp);
    assertThat(record.tcp()).isEqualTo(Optional.of(expectedTcpPort));
    assertThat(record.udp()).isEqualTo(Optional.of(expectedUdpPort));
  }

  private static Stream<Arguments> validEnrNodes() throws Exception {
    return Stream.of(
        Arguments.of(
            "enr:-KO4QK1ecw-CGrDDZ4YwFrhgqctD0tWMHKJhUVxsS4um3aUFe3yBHRtVL9uYKk16DurN1IdSKTOB1zNCvjBybjZ_KAq"
                + "GAYtJ5U8wg2V0aMfGhJsZKtCAgmlkgnY0gmlwhA_MtDmJc2VjcDI1NmsxoQNXD7fj3sscyOKBiHYy14igj1vJYWdKYZH7n3T8qRpIcYRzb"
                + "mFwwIN0Y3CCdl-DdWRwgnZf",
            Bytes.fromHexString(
                "0x570fb7e3decb1cc8e281887632d788a08f5bc961674a6191fb9f74fca91a4871957e3775d4bdfd4fdeff9bff92ad2f5965234d0e"
                    + "3c04ab4b85ab3eabd3193c35"),
            InetAddress.getByAddress(new byte[] {15, (byte) 204, (byte) 180, 57}),
            30303,
            30303),
        Arguments.of(
            "enr:-Jy4QK1ecw-CGrDDZ4YwFrhgqctD0tWMHKJhUVxsS4um3aUFe3yBHRtVL9uYKk16DurN1IdSKTOB1zNCvjBybjZ_KAq"
                + "GAYtJ5U8wg2V0aMfGhJsZKtCAgmlkgnY0gmlwhA_MtDmJc2VjcDI1NmsxoQNXD7fj3sscyOKBiHYy14igj1vJYWdKYZH7n3T8qRpIcYRzb"
                + "mFwwIN0Y3CCdl8=",
            Bytes.fromHexString(
                "0x570fb7e3decb1cc8e281887632d788a08f5bc961674a6191fb9f74fca91a4871957e3775d4bdfd4fdeff9bff92ad2f5965234d0e"
                    + "3c04ab4b85ab3eabd3193c35"),
            InetAddress.getByAddress(new byte[] {15, (byte) 204, (byte) 180, 57}),
            30303,
            30303));
  }

  /**
   * A vnt record keeps its key under a different field, and that key is the node id as a whole, not
   * the compressed classical key a v4 record stores.
   */
  @Test
  void aVntRecordYieldsTheWholeHybridKey() {
    final CompositePublicKey hybridKey =
        (CompositePublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();
    final Bytes encodedKey = Bytes.wrap(hybridKey.getEncoded());

    final EthereumNodeRecord record = EthereumNodeRecord.fromNodeRecord(vntRecord(encodedKey));

    assertThat(record.publicKey()).isEqualTo(encodedKey);
    assertThat(record.tcp()).contains(30304);
    assertThat(record.udp()).contains(30303);
  }

  private static NodeRecord vntRecord(final Bytes hybridKey) {
    return NodeRecordFactory.DEFAULT.createFromValues(
        UInt64.ONE,
        new EnrField(EnrField.ID, IdentitySchema.VNT),
        new EnrField(EnrField.PKEY_SECP256K1_MLDSA44, hybridKey),
        new EnrField(EnrField.IP_V4, Bytes.of(127, 0, 0, 1)),
        new EnrField(EnrField.UDP, 30303),
        new EnrField(EnrField.TCP, 30304));
  }
}
