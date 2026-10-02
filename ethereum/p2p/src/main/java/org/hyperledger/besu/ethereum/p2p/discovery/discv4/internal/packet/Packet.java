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

import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.ethereum.p2p.discovery.discv4.internal.PacketType;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

/**
 * A discv4 packet, laid out as {@code hash || signature || public key || type || data}.
 *
 * <p>The offsets follow the node's active DSA rather than being fixed, because a hybrid signature
 * is 2485 bytes where a classical one is 65.
 *
 * <p>Only the half of the public key that cannot be recovered travels on the wire: ML-DSA-44 has
 * no public key recovery, so the receiver would otherwise have no way to complete the sender's
 * identity. The classical half is recovered from its own half of the signature, exactly as a
 * flexible transaction does. A node whose active DSA is classical therefore sends no key at all
 * and keeps the discv4 layout unchanged, with the type byte back at offset 97.
 */
public class Packet {
  /** Length of the leading keccak256 integrity hash. */
  public static final int HASH_LENGTH = 32;

  /** The signature follows the hash. */
  public static final int SIGNATURE_INDEX = HASH_LENGTH;

  private final PacketType type;
  private final PacketData data;
  private final Bytes hash;
  private final Signature signature;
  private final PublicKey publicKey;

  /** Where the sender's partial public key starts, once the signature has been read. */
  public static int publicKeyIndex() {
    return SIGNATURE_INDEX + activeParams().getSignatureLength();
  }

  /**
   * How many bytes of public key the wire carries: the half whose algorithm cannot recover it, or
   * none at all when every half can.
   *
   * @return the length, zero for a classical node
   */
  public static int publicKeyLength() {
    return DSAProviderFactory.getActiveDSA()
            instanceof HybridDigitalSignatureAlgorithm hybrid
        ? hybrid.getSecondAlgorithm().getDsaParametersSet().getPublicKeyLength()
        : 0;
  }

  /** Where the single type byte sits. */
  public static int packetTypeIndex() {
    return publicKeyIndex() + publicKeyLength();
  }

  /** Where the RLP payload starts. */
  public static int packetDataIndex() {
    return packetTypeIndex() + 1;
  }

  private static DSAParametersSet activeParams() {
    return DSAProviderFactory.getActiveDsaParametersSet();
  }

  Packet(
      final PacketType type,
      final PacketData data,
      final Bytes hash,
      final Signature signature,
      final PublicKey publicKey) {
    this.type = type;
    this.data = data;
    this.hash = hash;
    this.signature = signature;
    this.publicKey = publicKey;
  }

  public PacketData getPacketData() {
    return data;
  }

  @SuppressWarnings("unchecked")
  public <T extends PacketData> Optional<T> getPacketData(final Class<T> expectedPacketType) {
    if (data == null || !data.getClass().equals(expectedPacketType)) {
      return Optional.empty();
    }
    return Optional.of((T) data);
  }

  /**
   * The sender's key, assembled from what the packet carried and what was recovered from the
   * signature.
   *
   * @return the sender's public key
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  public Bytes getNodeId() {
    return Bytes.wrap(publicKey.getEncoded());
  }

  public PacketType getType() {
    return type;
  }

  public Bytes getHash() {
    return hash;
  }

  public Signature getSignature() {
    return signature;
  }

  @Override
  public String toString() {
    return "Packet{"
        + "type="
        + type
        + ", data="
        + data
        + ", hash="
        + hash
        + ", signature="
        + signature
        + ", publicKey="
        + publicKey
        + '}';
  }
}
