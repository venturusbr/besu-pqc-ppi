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

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.ethereum.p2p.discovery.PeerDiscoveryPacketDecodingException;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.PacketType;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.enrrequest.EnrRequestPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.enrrequest.EnrRequestPacketDataRlpWriter;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.enrresponse.EnrResponsePacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.enrresponse.EnrResponsePacketDataRlpWriter;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.findneighbors.FindNeighborsPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.findneighbors.FindNeighborsPacketDataRlpWriter;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.neighbors.NeighborsPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.neighbors.NeighborsPacketDataRlpWriter;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.ping.PingPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.ping.PingPacketDataRlpWriter;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.pong.PongPacketData;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.packet.pong.PongPacketDataRlpWriter;
import org.hyperledger.besu.ethereum.rlp.RLP;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

@Singleton
public class PacketFactory {

  /** What a discv4 packet signature is called in the sign and verify metrics. */
  private static final String DISCV4_PACKET = "discv4-packet";

  private final PingPacketDataRlpWriter pingPacketDataRlpWriter;
  private final PongPacketDataRlpWriter pongPacketDataRlpWriter;
  private final FindNeighborsPacketDataRlpWriter findNeighborsPacketDataRlpWriter;
  private final NeighborsPacketDataRlpWriter neighborsPacketDataRlpWriter;
  private final EnrRequestPacketDataRlpWriter enrRequestPacketDataRlpWriter;
  private final EnrResponsePacketDataRlpWriter enrResponsePacketDataRlpWriter;
  private final PacketSignatureEncoder packetSignatureEncoder;

  public @Inject PacketFactory(
      final PingPacketDataRlpWriter pingPacketDataRlpWriter,
      final PongPacketDataRlpWriter pongPacketDataRlpWriter,
      final FindNeighborsPacketDataRlpWriter findNeighborsPacketDataRlpWriter,
      final NeighborsPacketDataRlpWriter neighborsPacketDataRlpWriter,
      final EnrRequestPacketDataRlpWriter enrRequestPacketDataRlpWriter,
      final EnrResponsePacketDataRlpWriter enrResponsePacketDataRlpWriter,
      final PacketSignatureEncoder packetSignatureEncoder) {
    this.pingPacketDataRlpWriter = pingPacketDataRlpWriter;
    this.pongPacketDataRlpWriter = pongPacketDataRlpWriter;
    this.findNeighborsPacketDataRlpWriter = findNeighborsPacketDataRlpWriter;
    this.neighborsPacketDataRlpWriter = neighborsPacketDataRlpWriter;
    this.enrRequestPacketDataRlpWriter = enrRequestPacketDataRlpWriter;
    this.enrResponsePacketDataRlpWriter = enrResponsePacketDataRlpWriter;
    this.packetSignatureEncoder = packetSignatureEncoder;
  }

  public Packet create(final PacketType type, final PacketData data, final NodeKey nodeKey) {
    final Bytes typeBytes = Bytes.of(type.getValue());
    final Bytes dataBytes =
        RLP.encode(
            (rlpOutput) -> {
              switch (type) {
                case PING -> pingPacketDataRlpWriter.writeTo((PingPacketData) data, rlpOutput);
                case PONG -> pongPacketDataRlpWriter.writeTo((PongPacketData) data, rlpOutput);
                case FIND_NEIGHBORS ->
                    findNeighborsPacketDataRlpWriter.writeTo(
                        (FindNeighborsPacketData) data, rlpOutput);
                case NEIGHBORS ->
                    neighborsPacketDataRlpWriter.writeTo((NeighborsPacketData) data, rlpOutput);
                case ENR_REQUEST ->
                    enrRequestPacketDataRlpWriter.writeTo((EnrRequestPacketData) data, rlpOutput);
                case ENR_RESPONSE ->
                    enrResponsePacketDataRlpWriter.writeTo((EnrResponsePacketData) data, rlpOutput);
              }
            });

    Signature signature =
        nodeKey.sign(Hash.keccak256(Bytes.wrap(typeBytes, dataBytes)), DISCV4_PACKET);
    PublicKey publicKey = nodeKey.getPublicKey();

    // The hash covers everything after itself, so the key bytes on the wire are bound to the
    // packet by it: swapping them alone breaks the integrity check.
    Bytes32 hash =
        Hash.keccak256(
            Bytes.concatenate(
                packetSignatureEncoder.encodeSignature(signature),
                partialPublicKey(publicKey),
                typeBytes,
                dataBytes));

    return new Packet(type, data, hash, signature, publicKey);
  }

  public Packet create(
      final PacketType packetType, final PacketData packetData, final Bytes message) {
    final DSAParametersSet params = DSAProviderFactory.getActiveDsaParametersSet();
    final int publicKeyIndex = Packet.publicKeyIndex();
    final int packetTypeIndex = Packet.packetTypeIndex();

    final Bytes hash = message.slice(0, Packet.SIGNATURE_INDEX);
    final Bytes encodedSignature =
        message.slice(Packet.SIGNATURE_INDEX, params.getSignatureLength());
    final Bytes encodedPublicKey = message.slice(publicKeyIndex, Packet.publicKeyLength());
    final Bytes signedPayload = message.slice(packetTypeIndex, message.size() - packetTypeIndex);

    // Perform hash integrity check.
    final Bytes rest =
        message.slice(Packet.SIGNATURE_INDEX, message.size() - Packet.SIGNATURE_INDEX);
    if (!Arrays.equals(Hash.keccak256(rest).toArray(), hash.toArray())) {
      throw new PeerDiscoveryPacketDecodingException(
          "Integrity check failed: non-matching hashes.");
    }

    final Signature signature = SignatureFactory.createSignatureFromBytes(encodedSignature, params);
    final Bytes32 recoveryHash = Hash.keccak256(signedPayload);
    final DigitalSignatureAlgorithm activeDsa = DSAProviderFactory.getActiveDSA();

    // The node id is assembled the way a flexible transaction assembles its sender: the classical
    // half is recovered from its half of the signature, and the half that cannot be recovered is
    // the one the packet carried. A forged classical half therefore yields a different node id
    // rather than an impersonation, which is what authenticates it.
    final PublicKey publicKey =
        PublicKeyHandler.resolvePublicKey(
                activeDsa, signature, partialPublicKey(encodedPublicKey, activeDsa), recoveryHash)
            .orElseThrow(
                () ->
                    new PeerDiscoveryPacketDecodingException(
                        "Invalid packet: the sender's public key could not be resolved"));

    // Verifies the half that is not covered by the recovery above. A classical key is recovered
    // whole, and a recovered key always verifies against its own signature, so there is nothing
    // left to check.
    if (!(activeDsa instanceof PublicKeyRecoverable)
        && !MetricWriters.timeVerification(
            DISCV4_PACKET,
            activeDsa.getDsaParametersSet(),
            () -> Boolean.TRUE.equals(activeDsa.verify(recoveryHash, signature, publicKey)))) {
      throw new PeerDiscoveryPacketDecodingException(
          "Invalid packet signature for the sender's public key");
    }

    return new Packet(packetType, packetData, hash, signature, publicKey);
  }

  /** The bytes of the sender's key that go on the wire, which is the half without recovery. */
  private static Bytes partialPublicKey(final PublicKey publicKey) {
    return publicKey instanceof CompositePublicKey composite
        ? Bytes.wrap(composite.getSecondKey().getEncoded())
        : Bytes.EMPTY;
  }

  /** The same half, read back off the wire, or empty when the algorithm carries none. */
  private static Optional<PublicKey> partialPublicKey(
      final Bytes encoded, final DigitalSignatureAlgorithm activeDsa) {
    if (!(activeDsa instanceof HybridDigitalSignatureAlgorithm hybrid)) {
      return Optional.empty();
    }
    return KeyFactory.createPublicKey(encoded, hybrid.getSecondAlgorithm().getDsaParametersSet());
  }
}
