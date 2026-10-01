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
package org.hyperledger.besu.ethereum.p2p.discovery;

import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;

import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies the signature of a node record received from the network.
 *
 * <p>A record is only worth trusting if it proves possession of the key it advertises: the node id
 * is derived from that key, so an unverified record lets a peer claim any identity it likes.
 *
 * <p>The {@code v4} scheme is verified by the discovery library itself, inside {@link
 * NodeRecord#isValid()}. The {@code vnt} scheme is not, deliberately: the library has no ML-DSA-44
 * implementation, so hybrid verification belongs here, where the DSA provider does. This class
 * covers both, so callers have a single place to ask.
 */
public class EnrSignatureValidator {

  private static final Logger LOG = LoggerFactory.getLogger(EnrSignatureValidator.class);

  /**
   * Whether the record is structurally sound and carries a signature made by the key it advertises.
   *
   * @param nodeRecord the record as it arrived
   * @return true when the record can be trusted to speak for its node id
   */
  public boolean isValid(final NodeRecord nodeRecord) {
    if (nodeRecord.getIdentityScheme() == IdentitySchema.VNT) {
      return isSecp256k1MlDsa44SignatureValid(nodeRecord);
    }
    // Every other scheme carries its own verification in the library: v4 checks the secp256k1
    // field and the ECDSA signature over the same preimage.
    if (!nodeRecord.isValid()) {
      LOG.trace("Node record rejected: failed the identity scheme's own checks. {}", nodeRecord);
      return false;
    }
    return true;
  }

  /**
   * Verifies a {@code vnt} record, which is {@link DSAParametersSet#SECP256K1MLDSA44} and nothing
   * else: it reads the composite key out of {@link EnrField#PKEY_SECP256K1_MLDSA44} and splits the
   * signature into its two halves, so it does not generalise to another hybrid pairing.
   *
   * <p>The two halves are checked separately on purpose. The node's active DSA covers the
   * ML-DSA-44 half; it deliberately skips any half whose algorithm supports public key recovery,
   * because such a signature is authenticated by recovering the key rather than by verifying
   * against a given one. A transaction gets that for free, since its sender address is derived
   * from the recovered key. A record does not, so the recovery and the comparison happen here.
   */
  private boolean isSecp256k1MlDsa44SignatureValid(final NodeRecord nodeRecord) {
    final DSAParametersSet params = DSAParametersSet.SECP256K1MLDSA44;

    final Object advertisedKey = nodeRecord.get(EnrField.PKEY_SECP256K1_MLDSA44);
    if (!(advertisedKey instanceof Bytes keyBytes)) {
      LOG.trace("Node record rejected: {} is not a byte string.", EnrField.PKEY_SECP256K1_MLDSA44);
      return false;
    }
    if (keyBytes.size() != params.getPublicKeyLength()) {
      LOG.trace(
          "Node record rejected: hybrid public key is {} bytes, expected {}.",
          keyBytes.size(),
          params.getPublicKeyLength());
      return false;
    }

    final Bytes signatureBytes = nodeRecord.getSignature();
    if (signatureBytes.size() != params.getSignatureLength()) {
      LOG.trace(
          "Node record rejected: hybrid signature is {} bytes, expected {}.",
          signatureBytes.size(),
          params.getSignatureLength());
      return false;
    }

    try {
      final Optional<PublicKey> maybeKey = KeyFactory.createPublicKey(keyBytes, params);
      if (maybeKey.isEmpty() || !(maybeKey.get() instanceof CompositePublicKey publicKey)) {
        LOG.trace("Node record rejected: the advertised hybrid public key could not be decoded.");
        return false;
      }

      final Signature decoded = SignatureFactory.createSignatureFromBytes(signatureBytes, params);
      if (!(decoded instanceof CompositeSignature signature)) {
        LOG.trace("Node record rejected: the signature is not a composite one.");
        return false;
      }

      // The same preimage both halves were signed over: NodeRecordManager signs the keccak256 of
      // the signature-less encoding.
      final Bytes32 preimage = Hash.keccak256(nodeRecord.serializeNoSignature());

      if (!isMlDsaHalfValid(preimage, signature, publicKey)) {
        LOG.trace("Node record rejected: the ML-DSA-44 signature does not verify. {}", nodeRecord);
        return false;
      }
      if (!isRecoverableHalfValid(preimage, signature, publicKey)) {
        LOG.trace(
            "Node record rejected: the recovered secp256k1 key is not the advertised one. {}",
            nodeRecord);
        return false;
      }
      return true;
    } catch (final RuntimeException e) {
      // A record arrives from the network, so malformed key or signature bytes are an expected
      // input rather than a bug: reject the record instead of letting it reach the caller.
      LOG.trace("Node record rejected: hybrid signature could not be checked.", e);
      return false;
    }
  }

  /**
   * The active DSA verifies the ML-DSA-44 half and waves the classical one through, since a
   * recoverable signature is authenticated by recovering its key rather than by verifying against
   * a given one.
   */
  private static boolean isMlDsaHalfValid(
      final Bytes32 data, final CompositeSignature signature, final CompositePublicKey key) {
    return DSAProviderFactory.getActiveDSA().verify(data, signature, key);
  }

  /**
   * Does that recovery and compares the result with the key the record states.
   *
   * <p>A flexible transaction gets this for free: its sender address is derived from the recovered
   * key, so a forged classical half simply produces a different sender. A record states its own
   * key instead of deriving it, so nothing forces the stated key and the recovered one to agree
   * unless they are compared here. The same is true of a discovery packet, which is why that one
   * assembles its node id through public key recovery rather than trusting a stated key.
   */
  private static boolean isRecoverableHalfValid(
      final Bytes32 data, final CompositeSignature signature, final CompositePublicKey key) {
    if (!(signature.getFirstSignature() instanceof SECPSignature ecdsaSignature)) {
      return false;
    }
    final Optional<SECPPublicKey> recovered =
        SignatureAlgorithmFactory.getInstance().recoverPublicKeyFromSignature(data, ecdsaSignature);
    // Compared on the key material alone: SECPPublicKey.equals also compares the algorithm label
    // it was built with, which differs between a recovered key and one that was decoded.
    return recovered.isPresent()
        && Bytes.wrap(recovered.get().getEncoded())
            .equals(Bytes.wrap(key.getFirstKey().getEncoded()));
  }
}
