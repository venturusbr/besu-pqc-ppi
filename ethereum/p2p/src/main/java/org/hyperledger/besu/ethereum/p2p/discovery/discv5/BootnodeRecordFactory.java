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

import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.plugin.data.EnodeURL;

import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the node records that DiscV5 pings to bootstrap its routing table.
 *
 * <p>Bootnodes are configured as enode URLs, but DiscV5 bootstraps from node records. A record
 * built here is unsigned and carries only what the bootstrap ping needs: the node id, the public
 * key the handshake encrypts to, and the address. The real record is received from the peer during
 * the handshake and replaces this one.
 */
public final class BootnodeRecordFactory {
  private static final Logger LOG = LoggerFactory.getLogger(BootnodeRecordFactory.class);

  private static final int HYBRID_KEY_SIZE = DSAParametersSet.SECP256K1MLDSA44.getPublicKeyLength();
  private static final int SECP_KEY_SIZE = DSAParametersSet.SECP256K1.getPublicKeyLength();

  private BootnodeRecordFactory() {
    // utility class
  }

  /**
   * Converts bootnode enode URLs into the node records to bootstrap from, dropping any that cannot
   * be converted.
   *
   * @param bootnodes the configured bootnodes
   * @return the records to ping on startup
   */
  public static List<NodeRecord> buildBootnodeRecords(final List<EnodeURL> bootnodes) {
    final List<NodeRecord> records =
        bootnodes.stream()
            .map(BootnodeRecordFactory::toNodeRecord)
            .flatMap(Optional::stream)
            .toList();
    LOG.info("DiscV5 will bootstrap from {} of {} bootnodes", records.size(), bootnodes.size());
    return records;
  }

  private static Optional<NodeRecord> toNodeRecord(final EnodeURL enode) {
    try {
      final Bytes nodeId = enode.getNodeId();
      final int discoveryPort = enode.getDiscoveryPortOrZero();
      final int listeningPort = enode.getListeningPortOrZero();

      // The identity scheme follows the key the enode carries: a hybrid key is published whole
      // under the vnt scheme, a classical one compressed under v4.
      final EnrField publicKeyField;
      final IdentitySchema identitySchema;
      if (nodeId.size() == HYBRID_KEY_SIZE) {
        identitySchema = IdentitySchema.VNT;
        publicKeyField = new EnrField(EnrField.PKEY_SECP256K1_MLDSA44, nodeId);
      } else if (nodeId.size() == SECP_KEY_SIZE) {
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
        identitySchema = IdentitySchema.V4;
        publicKeyField =
            new EnrField(
                EnrField.PKEY_SECP256K1,
                signatureAlgorithm.compressPublicKey(signatureAlgorithm.createPublicKey(nodeId)));
      } else {
        LOG.warn(
            "Ignoring bootnode {}: node id of {} bytes matches no known signature algorithm",
            enode,
            nodeId.size());
        return Optional.empty();
      }

      return Optional.of(
          NodeRecordFactory.DEFAULT.createFromValues(
              UInt64.ONE,
              new EnrField(EnrField.ID, identitySchema),
              publicKeyField,
              new EnrField(EnrField.IP_V4, Bytes.of(enode.getIp().getAddress())),
              new EnrField(EnrField.UDP, discoveryPort),
              new EnrField(EnrField.TCP, listeningPort)));
    } catch (final RuntimeException e) {
      LOG.warn("Ignoring bootnode {}: {}", enode, e.getMessage());
      return Optional.empty();
    }
  }
}
