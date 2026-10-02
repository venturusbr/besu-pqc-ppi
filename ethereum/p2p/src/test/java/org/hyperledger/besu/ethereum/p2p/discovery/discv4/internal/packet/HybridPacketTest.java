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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.ethereum.p2p.discovery.PeerDiscoveryPacketDecodingException;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.Endpoint;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.PeerDiscoveryAgentV4;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.DiscoveryPeerV4;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.PacketType;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.findneighbors.FindNeighborsPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.ping.PingPacketData;

import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.vertx.core.buffer.Buffer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The hybrid path through the packet envelope, which the rest of the packet tests never reach
 * because they run with a classical DSA where no public key travels at all.
 *
 * <p>Only the ML-DSA-44 half of the key is on the wire: the classical half is recovered from its
 * half of the signature, as a flexible transaction does with its sender.
 */
class HybridPacketTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private PacketPackage packetPackage;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(HYBRID.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    packetPackage = DaggerPacketPackage.create();
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void theEnvelopeCarriesOnlyTheHalfThatCannotBeRecovered() {
    assertThat(Packet.publicKeyLength()).isEqualTo(DSAParametersSet.MLDSA44.getPublicKeyLength());
    assertThat(Packet.publicKeyIndex())
        .isEqualTo(Packet.SIGNATURE_INDEX + HYBRID.getSignatureLength());
    assertThat(Packet.packetTypeIndex())
        .isEqualTo(
            Packet.SIGNATURE_INDEX
                + HYBRID.getSignatureLength()
                + DSAParametersSet.MLDSA44.getPublicKeyLength());
  }

  @Test
  void aSignedPacketSurvivesTheRoundTripAndKeepsItsNodeId()
      throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = hybridKeyPair();
    final Packet sent = pingSignedBy(keyPair);

    final Buffer encoded = packetPackage.packetSerializer().encode(sent);
    final Packet received = packetPackage.packetDeserializer().decode(encoded);

    // the whole hybrid key, reassembled from the carried half and the recovered one
    assertThat(received.getNodeId()).isEqualTo(Bytes.wrap(keyPair.getPublicKey().getEncoded()));
    assertThat(received.getNodeId().size()).isEqualTo(HYBRID.getPublicKeyLength());
    assertThat(received.getPublicKey()).isInstanceOf(CompositePublicKey.class);
    assertThat(received.getType()).isEqualTo(PacketType.PING);
    assertThat(received.getSignature().encodedBytes()).isEqualTo(sent.getSignature().encodedBytes());
  }

  @Test
  void theWireLayoutPlacesTheMlDsaKeyWhereTheOffsetsSayItIs()
      throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = hybridKeyPair();
    final CompositePublicKey publicKey = (CompositePublicKey) keyPair.getPublicKey();

    final Bytes wire = Bytes.wrapBuffer(packetPackage.packetSerializer().encode(pingSignedBy(keyPair)));

    assertThat(wire.slice(Packet.publicKeyIndex(), Packet.publicKeyLength()))
        .isEqualTo(Bytes.wrap(publicKey.getSecondKey().getEncoded()));
    // the classical half is nowhere on the wire: it is recovered, not sent
    assertThat(wire.toHexString())
        .doesNotContain(Bytes.wrap(publicKey.getFirstKey().getEncoded()).toUnprefixedHexString());
    assertThat(wire.get(Packet.packetTypeIndex())).isEqualTo(PacketType.PING.getValue());
  }

  @Test
  void aPacketThatFitsTheRaisedSizeLimit() throws InvalidAlgorithmParameterException {
    final Bytes wire =
        Bytes.wrapBuffer(packetPackage.packetSerializer().encode(pingSignedBy(hybridKeyPair())));

    // a ping is the small one, and it already exceeds what the devp2p specification allows,
    // which is what the raised limit is for
    assertThat(wire.size()).isGreaterThan(1280);
    assertThat(wire.size()).isLessThanOrEqualTo(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES);
  }

  @Test
  void aTamperedMlDsaKeyIsRejected() throws InvalidAlgorithmParameterException {
    final Bytes wire =
        Bytes.wrapBuffer(packetPackage.packetSerializer().encode(pingSignedBy(hybridKeyPair())));

    final byte[] tampered = wire.toArray();
    tampered[Packet.publicKeyIndex()] ^= 0x01;

    assertThatThrownBy(
            () -> packetPackage.packetDeserializer().decode(Buffer.buffer(tampered)))
        .isInstanceOf(PeerDiscoveryPacketDecodingException.class);
  }

  @Test
  void aTamperedSignatureIsRejected() throws InvalidAlgorithmParameterException {
    final Bytes wire =
        Bytes.wrapBuffer(packetPackage.packetSerializer().encode(pingSignedBy(hybridKeyPair())));

    final byte[] tampered = wire.toArray();
    // deep inside the ML-DSA-44 half, past the classical signature
    tampered[Packet.publicKeyIndex() - 1] ^= 0x01;

    assertThatThrownBy(
            () -> packetPackage.packetDeserializer().decode(Buffer.buffer(tampered)))
        .isInstanceOf(PeerDiscoveryPacketDecodingException.class);
  }

  /**
   * A NEIGHBORS response has to fit the size the requester will accept, and with hybrid node ids
   * that is what caps how many peers one response can name. Thirteen of them, which is what the
   * classical layout allows, comes to about 22kB and would be dropped on arrival.
   */
  @Test
  void aFullNeighborsResponseFitsTheSizeLimit() throws InvalidAlgorithmParameterException {
    final int perPeer = 16 + 4 + 4 + HYBRID.getPublicKeyLength();
    final int fitting =
        Math.max(
            1,
            Math.min(
                13,
                (PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES - Packet.packetDataIndex() - 64)
                    / perPeer));

    final Bytes wire = Bytes.wrapBuffer(packetPackage.packetSerializer().encode(neighbors(fitting)));

    assertThat(wire.size()).isLessThanOrEqualTo(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES);
    // and one more would not fit, so the cap is where it belongs rather than merely safe
    final Bytes tooBig =
        Bytes.wrapBuffer(packetPackage.packetSerializer().encode(neighbors(fitting + 1)));
    assertThat(tooBig.size()).isGreaterThan(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES);
  }

  private Packet neighbors(final int peerCount) throws InvalidAlgorithmParameterException {
    final List<DiscoveryPeerV4> peers = new ArrayList<>();
    for (int i = 0; i < peerCount; i++) {
      peers.add(
          DiscoveryPeerV4.fromIdAndEndpoint(
              Bytes.wrap(hybridKeyPair().getPublicKey().getEncoded()),
              new Endpoint("127.0.0." + (i + 1), 30303, Optional.of(30304))));
    }
    return packetPackage
        .packetFactory()
        .create(
            PacketType.NEIGHBORS,
            packetPackage.neighborsPacketDataFactory().create(peers),
            nodeKeyOf(hybridKeyPair()));
  }

  /**
   * The lookup that discovery runs on every table refresh. Its target is a node id, so on a hybrid
   * node it is 1376 bytes; a validator that still expected the classical 64 rejected every one of
   * them, and nodes never asked their peers for neighbours.
   */
  @Test
  void aFindNeighborsWithAHybridTargetIsBuiltAndSurvivesTheRoundTrip()
      throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = hybridKeyPair();
    final Bytes target = Bytes.wrap(hybridKeyPair().getPublicKey().getEncoded());
    assertThat(target.size()).isEqualTo(HYBRID.getPublicKeyLength());

    final PacketData data = packetPackage.findNeighborsPacketDataFactory().create(target);
    final Packet sent =
        packetPackage.packetFactory().create(PacketType.FIND_NEIGHBORS, data, nodeKeyOf(keyPair));

    final Buffer encoded = packetPackage.packetSerializer().encode(sent);
    assertThat(encoded.length()).isLessThanOrEqualTo(PeerDiscoveryAgentV4.MAX_PACKET_SIZE_BYTES);

    final Packet received = packetPackage.packetDeserializer().decode(encoded);
    assertThat(received.getType()).isEqualTo(PacketType.FIND_NEIGHBORS);
    assertThat(received.getPacketData(FindNeighborsPacketData.class).orElseThrow().getTarget())
        .isEqualTo(target);
    assertThat(received.getNodeId()).isEqualTo(Bytes.wrap(keyPair.getPublicKey().getEncoded()));
  }

  @Test
  void aClassicalSizedTargetIsRejectedOnAHybridNode() {
    assertThatThrownBy(
            () ->
                packetPackage
                    .findNeighborsPacketDataFactory()
                    .create(Bytes.repeat((byte) 0x01, DSAParametersSet.SECP256K1.getPublicKeyLength())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("target must be a valid node id");
  }

  private Packet pingSignedBy(final KeyPair keyPair) {
    final PacketData data =
        packetPackage
            .pingPacketDataFactory()
            .create(
                Optional.of(new Endpoint("127.0.0.1", 30303, Optional.of(30304))),
                new Endpoint("127.0.0.2", 30303, Optional.of(30304)),
                UInt64.ONE);
    return packetPackage.packetFactory().create(PacketType.PING, data, nodeKeyOf(keyPair));
  }

  /** A node key that signs with the hybrid algorithm, which is all the factory asks of it. */
  private static NodeKey nodeKeyOf(final KeyPair keyPair) {
    final DigitalSignatureAlgorithm algorithm =
        new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();
    final NodeKey nodeKey = mock(NodeKey.class);
    when(nodeKey.getPublicKey()).thenReturn(keyPair.getPublicKey());
    when(nodeKey.sign(any(Bytes32.class), anyString()))
        .thenAnswer(call -> algorithm.sign(call.getArgument(0), keyPair.getPrivateKey()));
    return nodeKey;
  }

  private static KeyPair hybridKeyPair() throws InvalidAlgorithmParameterException {
    return new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get().generateNodeKeyPair();
  }
}
