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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.ethereum.chain.VariablesStorage;
import org.hyperledger.besu.ethereum.forkid.ForkId;
import org.hyperledger.besu.ethereum.forkid.ForkIdManager;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.nat.NatService;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The local node record follows the node's active DSA: a hybrid key publishes a vnt record signed
 * with a hybrid signature, a classical one keeps the v4 record the network already understands.
 */
class NodeRecordManagerTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;
  private static final String ADVERTISED_HOST = "127.0.0.1";
  private static final int DISCOVERY_PORT = 30303;
  private static final int TCP_PORT = 30304;

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void aHybridNodeKeyPublishesAVntRecord() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final CompositePublicKey publicKey = (CompositePublicKey) keyPair.getPublicKey();

    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.VNT);
    assertThat(record.get(EnrField.PKEY_SECP256K1_MLDSA44))
        .isEqualTo(Bytes.wrap(publicKey.getEncoded()));
    assertThat(record.get(EnrField.PKEY_SECP256K1)).isNull();
  }

  @Test
  void theVntSignatureIsHybridAndVerifies() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final DigitalSignatureAlgorithm algorithm =
        new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();

    final NodeRecord record = buildLocalRecord(keyPair);

    // the whole hybrid signature is published, not just its classical half
    assertThat(record.getSignature().size()).isEqualTo(HYBRID.getSignatureLength());
    final Signature signature =
        SignatureFactory.createSignatureFromBytes(record.getSignature(), HYBRID);
    assertThat(
            algorithm.verify(
                Hash.keccak256(record.serializeNoSignature()), signature, keyPair.getPublicKey()))
        .isTrue();
  }

  @Test
  void aVntRecordDerivesItsNodeIdFromTheWholeHybridKey() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final Bytes hybridKey = Bytes.wrap(keyPair.getPublicKey().getEncoded());

    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(record.getNodeId()).isEqualTo(Hash.keccak256(hybridKey));
  }

  @Test
  void aVntRecordSurvivesTheWireFormat() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();

    final NodeRecord record = buildLocalRecord(keyPair);
    final NodeRecord parsed = NodeRecordFactory.DEFAULT.fromBytes(record.serialize());

    assertThat(parsed.getNodeId()).isEqualTo(record.getNodeId());
    assertThat(parsed.getSignature()).isEqualTo(record.getSignature());
    assertThat(parsed.get(EnrField.PKEY_SECP256K1_MLDSA44))
        .isEqualTo(record.get(EnrField.PKEY_SECP256K1_MLDSA44));
  }

  @Test
  void aClassicalNodeKeyStillPublishesAV4Record() {
    final KeyPair keyPair = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.V4);
    assertThat(record.get(EnrField.PKEY_SECP256K1_MLDSA44)).isNull();
    // a v4 record carries r || s only, without the recovery id
    assertThat(record.getSignature().size())
        .isEqualTo(DSAParametersSet.SECP256K1.getSignatureLength() - 1);
    assertThat(record.isValid()).isTrue();
  }

  @Test
  void anUnchangedRecordIsReusedInsteadOfBeingResigned() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final VariablesStorage storage = inMemoryVariablesStorage();
    final NodeRecordManager manager = newManager(keyPair, storage);

    manager.initializeLocalNode(ADVERTISED_HOST, DISCOVERY_PORT, TCP_PORT);
    final NodeRecord first = localRecordOf(manager);

    manager.updateNodeRecord();
    final NodeRecord second = localRecordOf(manager);

    // nothing changed, so the sequence number must not move
    assertThat(second.getSeq()).isEqualTo(first.getSeq());
    assertThat(second.serialize()).isEqualTo(first.serialize());
  }

  @Test
  void aChangedForkIdReissuesTheRecord() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final VariablesStorage storage = inMemoryVariablesStorage();
    final NodeRecordManager manager = newManager(keyPair, storage);

    manager.initializeLocalNode(ADVERTISED_HOST, DISCOVERY_PORT, TCP_PORT);
    final NodeRecord beforeFork = localRecordOf(manager);

    // crossing a fork changes the eth field, which the record has to advertise
    currentForkIdHash[0] = Bytes.fromHexString("0xdeadbeef");
    manager.updateNodeRecord();
    final NodeRecord afterFork = localRecordOf(manager);

    assertThat(afterFork.getSeq()).isEqualTo(beforeFork.getSeq().add(1));
    assertThat(afterFork.get("eth")).isNotEqualTo(beforeFork.get("eth"));
  }

  private NodeRecord buildLocalRecord(final KeyPair keyPair) {
    final NodeRecordManager manager = newManager(keyPair, inMemoryVariablesStorage());
    manager.initializeLocalNode(ADVERTISED_HOST, DISCOVERY_PORT, TCP_PORT);
    return localRecordOf(manager);
  }

  private static NodeRecord localRecordOf(final NodeRecordManager manager) {
    return manager.getLocalNode().orElseThrow().getNodeRecord().orElseThrow();
  }

  /** The fork id the mocked manager reports, so a test can move the chain across a fork. */
  private final Bytes[] currentForkIdHash = {Bytes.fromHexString("0xc5c858b5")};

  private NodeRecordManager newManager(final KeyPair keyPair, final VariablesStorage storage) {
    final StorageProvider storageProvider = mock(StorageProvider.class);
    when(storageProvider.createVariablesStorage()).thenReturn(storage);

    final NodeKey nodeKey = mock(NodeKey.class);
    final PublicKey publicKey = keyPair.getPublicKey();
    when(nodeKey.getPublicKey()).thenReturn(publicKey);
    final DigitalSignatureAlgorithm algorithm = algorithmFor(publicKey);
    when(nodeKey.sign(any(Bytes32.class), anyString()))
        .thenAnswer(call -> algorithm.sign(call.getArgument(0), keyPair.getPrivateKey()));

    final ForkIdManager forkIdManager = mock(ForkIdManager.class);
    when(forkIdManager.getForkIdForChainHead())
        .thenAnswer(call -> new ForkId(currentForkIdHash[0], Bytes.EMPTY));

    final NatService natService = mock(NatService.class);
    when(natService.queryExternalIPAddress(anyString())).thenReturn(ADVERTISED_HOST);

    return new NodeRecordManager(storageProvider, nodeKey, forkIdManager, natService);
  }

  private static DigitalSignatureAlgorithm algorithmFor(final PublicKey publicKey) {
    return publicKey instanceof CompositePublicKey
        ? new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get()
        : SignatureAlgorithmFactory.getInstance();
  }

  /** Keeps the persisted record in memory, which is all the manager needs from storage. */
  private static VariablesStorage inMemoryVariablesStorage() {
    final VariablesStorage storage = mock(VariablesStorage.class);
    final Bytes[] stored = {null};
    when(storage.getLocalEnrSeqno()).thenAnswer(call -> Optional.ofNullable(stored[0]));
    final VariablesStorage.Updater updater = mock(VariablesStorage.Updater.class);
    when(storage.updater()).thenReturn(updater);
    org.mockito.Mockito.doAnswer(
            call -> {
              stored[0] = call.getArgument(0);
              return null;
            })
        .when(updater)
        .setLocalEnrSeqno(any(Bytes.class));
    return storage;
  }

  private static KeyPair useHybridDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(HYBRID.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    return new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get().generateNodeKeyPair();
  }
}
