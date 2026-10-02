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

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.ethereum.p2p.peers.EnodeURLImpl;
import org.hyperledger.besu.plugin.data.EnodeURL;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * DiscV5 bootstraps from node records, but bootnodes are configured as enode URLs. The records
 * built here only have to carry what the bootstrap ping needs: a node id, the key the handshake
 * encrypts to, and an address.
 */
class BootnodeRecordFactoryTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void aHybridEnodeBecomesAVntRecord() throws InvalidAlgorithmParameterException {
    useHybridDsa();
    final CompositePublicKey publicKey = hybridPublicKey();
    final Bytes nodeId = Bytes.wrap(publicKey.getEncoded());

    final NodeRecord record = onlyRecordOf(enodeWith(nodeId));

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.VNT);
    assertThat(record.get(EnrField.PKEY_SECP256K1_MLDSA44)).isEqualTo(nodeId);
    // the node id DiscV5 routes on has to match what the peer computes for itself
    assertThat(record.getNodeId()).isEqualTo(Hash.keccak256(nodeId));
  }

  @Test
  void aHybridRecordCarriesTheKeyTheHandshakeNeeds() throws InvalidAlgorithmParameterException {
    useHybridDsa();
    final CompositePublicKey publicKey = hybridPublicKey();
    final SignatureAlgorithm secp = SignatureAlgorithmFactory.getInstance();

    final NodeRecord record = onlyRecordOf(enodeWith(Bytes.wrap(publicKey.getEncoded())));

    assertThat(record.getSecp256k1PublicKey())
        .isEqualTo(
            secp.compressPublicKey(
                secp.createPublicKey(Bytes.wrap(publicKey.getFirstKey().getEncoded()))));
  }

  @Test
  void aClassicalEnodeBecomesAV4Record() {
    final Bytes nodeId =
        Bytes.wrap(
            SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey().getEncoded());

    final NodeRecord record = onlyRecordOf(enodeWith(nodeId));

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.V4);
    // v4 publishes the compressed key
    assertThat(((Bytes) record.get(EnrField.PKEY_SECP256K1)).size()).isEqualTo(33);
  }

  @Test
  void theAddressIsCarriedOver() {
    final Bytes nodeId =
        Bytes.wrap(
            SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey().getEncoded());

    final NodeRecord record =
        onlyRecordOf(
            EnodeURLImpl.builder()
                .nodeId(nodeId)
                .ipAddress("172.28.0.11")
                .listeningPort(30304)
                .discoveryPort(30303)
                .build());

    assertThat(record.getUdpAddress().orElseThrow().getPort()).isEqualTo(30303);
    assertThat(record.getTcpAddress().orElseThrow().getPort()).isEqualTo(30304);
    assertThat(record.getUdpAddress().orElseThrow().getAddress().getHostAddress())
        .isEqualTo("172.28.0.11");
  }

  @Test
  void anEmptyBootnodeListProducesNoRecords() {
    assertThat(BootnodeRecordFactory.buildBootnodeRecords(List.of())).isEmpty();
  }

  private static NodeRecord onlyRecordOf(final EnodeURL enode) {
    final List<NodeRecord> records = BootnodeRecordFactory.buildBootnodeRecords(List.of(enode));
    assertThat(records).hasSize(1);
    return records.get(0);
  }

  private static EnodeURL enodeWith(final Bytes nodeId) {
    return EnodeURLImpl.builder()
        .nodeId(nodeId)
        .ipAddress("127.0.0.1")
        .listeningPort(30303)
        .discoveryPort(30303)
        .build();
  }

  private static CompositePublicKey hybridPublicKey() {
    return (CompositePublicKey)
        new SupportedAlgorithms()
            .getDSAByName(HYBRID.getName())
            .get()
            .generateNodeKeyPair()
            .getPublicKey();
  }

  private static void useHybridDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(HYBRID.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }
}
