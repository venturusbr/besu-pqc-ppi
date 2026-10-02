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

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;

import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Records that arrive over discv5 are decoded by the factory handed to the discovery system, and
 * the library checks each one with {@link NodeRecord#isValid()}. That check has to cover the hybrid
 * signature, which the library's own vnt interpreter leaves out.
 */
class VerifyingVntInterpreterTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private final DigitalSignatureAlgorithm hybrid =
      new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();

  @BeforeEach
  void useHybridDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(HYBRID.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void acceptsARecordSignedByTheKeyItAdvertises() {
    final Bytes received = signedRecord(hybrid.generateNodeKeyPair()).serialize();

    assertThat(VerifyingVntInterpreter.nodeRecordFactory().fromBytes(received).isValid()).isTrue();
  }

  @Test
  void rejectsARecordWhoseSignatureWasTamperedWith() {
    final NodeRecord record = signedRecord(hybrid.generateNodeKeyPair());
    final byte[] tampered = record.getSignature().toArray();
    tampered[tampered.length - 1] ^= 0x01;
    record.setSignature(Bytes.wrap(tampered));
    final Bytes received = record.serialize();

    // the library's own interpreter only checks the record's structure
    assertThat(NodeRecordFactory.DEFAULT.fromBytes(received).isValid()).isTrue();

    assertThat(VerifyingVntInterpreter.nodeRecordFactory().fromBytes(received).isValid()).isFalse();
  }

  @Test
  void rejectsARecordSignedByAnotherKey() {
    final KeyPair advertised = hybrid.generateNodeKeyPair();
    final KeyPair signer = hybrid.generateNodeKeyPair();
    final NodeRecord record = unsignedRecord(advertised);
    sign(record, signer);

    assertThat(VerifyingVntInterpreter.nodeRecordFactory().fromBytes(record.serialize()).isValid())
        .isFalse();
  }

  private NodeRecord signedRecord(final KeyPair keyPair) {
    final NodeRecord record = unsignedRecord(keyPair);
    sign(record, keyPair);
    return record;
  }

  private static NodeRecord unsignedRecord(final KeyPair keyPair) {
    return NodeRecordFactory.DEFAULT.createFromValues(
        UInt64.ONE,
        new EnrField(EnrField.ID, IdentitySchema.VNT),
        new EnrField(
            EnrField.PKEY_SECP256K1_MLDSA44, Bytes.wrap(keyPair.getPublicKey().getEncoded())),
        new EnrField(EnrField.IP_V4, Bytes.wrap(InetAddress.getLoopbackAddress().getAddress())),
        new EnrField(EnrField.UDP, 30303));
  }

  /** Signs as NodeRecordManager does: the keccak256 of the signature-less encoding. */
  private void sign(final NodeRecord record, final KeyPair keyPair) {
    record.setSignature(
        hybrid
            .sign(Hash.keccak256(record.serializeNoSignature()), keyPair.getPrivateKey())
            .encodedBytes());
  }
}
