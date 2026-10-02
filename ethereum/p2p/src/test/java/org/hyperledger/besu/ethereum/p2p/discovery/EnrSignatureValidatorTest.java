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
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
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
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A record only earns trust by proving possession of the key it advertises, since the node id is
 * derived from that key. These cover the hybrid path, which the discovery library leaves to Besu.
 */
class EnrSignatureValidatorTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;
  private static final String ADVERTISED_HOST = "127.0.0.1";
  private static final int DISCOVERY_PORT = 30303;
  private static final int TCP_PORT = 30304;

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void acceptsAHybridRecordSignedByTheKeyItAdvertises() throws InvalidAlgorithmParameterException {
    final NodeRecord record = buildLocalRecord(useHybridDsa());

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.VNT);
    assertThat(validator().isValid(record)).isTrue();
  }

  @Test
  void rejectsAHybridRecordWhoseSignatureWasTamperedWith()
      throws InvalidAlgorithmParameterException {
    final NodeRecord record = buildLocalRecord(useHybridDsa());

    final Bytes original = record.getSignature();
    final byte[] tampered = original.toArray();
    // flip a bit deep inside the ML-DSA-44 half, past the classical signature
    tampered[original.size() - 1] ^= 0x01;
    record.setSignature(Bytes.wrap(tampered));

    assertThat(validator().isValid(record)).isFalse();
  }

  @Test
  void rejectsAHybridRecordCarryingAnotherNodesSignature()
      throws InvalidAlgorithmParameterException {
    final KeyPair ours = useHybridDsa();
    final NodeRecord ourRecord = buildLocalRecord(ours);
    final NodeRecord theirRecord = buildLocalRecord(hybridKeyPair());

    // a well-formed hybrid signature, just not over this record
    ourRecord.setSignature(theirRecord.getSignature());

    assertThat(validator().isValid(ourRecord)).isFalse();
  }

  @Test
  void rejectsAHybridRecordWhoseSignatureIsTheWrongLength()
      throws InvalidAlgorithmParameterException {
    final NodeRecord record = buildLocalRecord(useHybridDsa());

    // the classical half alone, as a v4 record would carry
    record.setSignature(record.getSignature().slice(0, 64));

    assertThat(validator().isValid(record)).isFalse();
  }

  @Test
  void acceptsAClassicalRecord() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useClassicalDsa();

    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(record.getIdentityScheme()).isEqualTo(IdentitySchema.V4);
    assertThat(validator().isValid(record)).isTrue();
  }

  @Test
  void rejectsAClassicalRecordWhoseSignatureWasTamperedWith()
      throws InvalidAlgorithmParameterException {
    final NodeRecord record = buildLocalRecord(useClassicalDsa());

    final byte[] tampered = record.getSignature().toArray();
    tampered[0] ^= 0x01;
    record.setSignature(Bytes.wrap(tampered));

    assertThat(validator().isValid(record)).isFalse();
  }

  /**
   * The case the recovery check exists for. The hybrid DSA does not verify the secp256k1 half,
   * which is meant to be authenticated by recovery, so an attacker holding only the ML-DSA-44 half
   * could otherwise forge a record: keep a well-formed classical signature made by some other key,
   * and re-sign the ML-DSA half over it so the nesting still lines up. Only recovering the
   * classical key and comparing it to the one the record advertises catches that.
   */
  @Test
  void rejectsAHybridRecordWhoseClassicalHalfBelongsToAnotherKey()
      throws InvalidAlgorithmParameterException {
    final KeyPair victim = useHybridDsa();
    final NodeRecord record = buildLocalRecord(victim);
    final Bytes32 preimage = Hash.keccak256(record.serializeNoSignature());

    // a classical signature over the same preimage, but made by a key the victim does not hold
    final KeyPair attacker = hybridKeyPair();
    final Signature foreignEcdsa =
        SignatureAlgorithmFactory.getInstance().sign(preimage, secpHalfOf(attacker));

    // the ML-DSA half is re-made over data || foreignEcdsa, which is what strong nesting signs,
    // so that half verifies cleanly
    final DigitalSignatureAlgorithm mldsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();
    final Signature reforgedMlDsa =
        mldsa.sign(
            Bytes.concatenate(preimage, foreignEcdsa.encodedBytes()),
            ((CompositePrivateKey) victim.getPrivateKey()).getSecondKey());

    record.setSignature(
        SignatureFactory.createCompositeConcSignature(foreignEcdsa, reforgedMlDsa).encodedBytes());

    // the hybrid DSA alone is happy with this record, which is exactly the gap being closed
    assertThat(
            DSAProviderFactory.getVerifierProvider()
                .getActiveDSA()
                .verify(
                    preimage,
                    SignatureFactory.createSignatureFromBytes(record.getSignature(), HYBRID),
                    victim.getPublicKey()))
        .isTrue();

    assertThat(validator().isValid(record)).isFalse();
  }

  @Test
  void acceptsAHybridRecordFromTheNodeItBelongsTo() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useHybridDsa();
    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(validator().isValidFor(record, nodeIdOf(keyPair))).isTrue();
  }

  /**
   * A genuine record replayed by another peer: its signature holds up, but it speaks for a
   * different node than the one that sent it.
   */
  @Test
  void rejectsAHybridRecordReplayedByAnotherPeer() throws InvalidAlgorithmParameterException {
    final NodeRecord victimRecord = buildLocalRecord(useHybridDsa());
    final KeyPair sender = hybridKeyPair();

    assertThat(validator().isValid(victimRecord)).isTrue();
    assertThat(validator().isValidFor(victimRecord, nodeIdOf(sender))).isFalse();
  }

  @Test
  void acceptsAClassicalRecordFromTheNodeItBelongsTo() throws InvalidAlgorithmParameterException {
    final KeyPair keyPair = useClassicalDsa();
    final NodeRecord record = buildLocalRecord(keyPair);

    assertThat(validator().isValidFor(record, nodeIdOf(keyPair))).isTrue();
  }

  @Test
  void rejectsAClassicalRecordReplayedByAnotherPeer() throws InvalidAlgorithmParameterException {
    final NodeRecord victimRecord = buildLocalRecord(useClassicalDsa());
    final KeyPair sender = SignatureAlgorithmFactory.getInstance().generateKeyPair();

    assertThat(validator().isValid(victimRecord)).isTrue();
    assertThat(validator().isValidFor(victimRecord, nodeIdOf(sender))).isFalse();
  }

  /** A discovery peer id is the encoded public key: 64 bytes classical, the whole key hybrid. */
  private static Bytes nodeIdOf(final KeyPair keyPair) {
    return Bytes.wrap(keyPair.getPublicKey().getEncoded());
  }

  private static SECPPrivateKey secpHalfOf(final KeyPair hybrid) {
    return (SECPPrivateKey) ((CompositePrivateKey) hybrid.getPrivateKey()).getFirstKey();
  }

  private static EnrSignatureValidator validator() {
    return new EnrSignatureValidator();
  }

  private NodeRecord buildLocalRecord(final KeyPair keyPair) {
    final NodeRecordManager manager = newManager(keyPair);
    manager.initializeLocalNode(ADVERTISED_HOST, DISCOVERY_PORT, TCP_PORT);
    return manager.getLocalNode().orElseThrow().getNodeRecord().orElseThrow();
  }

  private NodeRecordManager newManager(final KeyPair keyPair) {
    // built before the stubbing below: it stubs a mock of its own, and Mockito rejects that
    // happening inside an unfinished when(...)
    final VariablesStorage variablesStorage = inMemoryVariablesStorage();
    final StorageProvider storageProvider = mock(StorageProvider.class);
    when(storageProvider.createVariablesStorage()).thenReturn(variablesStorage);

    final NodeKey nodeKey = mock(NodeKey.class);
    final PublicKey publicKey = keyPair.getPublicKey();
    when(nodeKey.getPublicKey()).thenReturn(publicKey);
    final DigitalSignatureAlgorithm algorithm = algorithmFor(publicKey);
    when(nodeKey.sign(any(Bytes32.class), anyString()))
        .thenAnswer(call -> algorithm.sign(call.getArgument(0), keyPair.getPrivateKey()));

    final ForkIdManager forkIdManager = mock(ForkIdManager.class);
    when(forkIdManager.getForkIdForChainHead())
        .thenReturn(new ForkId(Bytes.fromHexString("0xc5c858b5"), Bytes.EMPTY));

    final NatService natService = mock(NatService.class);
    when(natService.queryExternalIPAddress(anyString())).thenReturn(ADVERTISED_HOST);

    return new NodeRecordManager(storageProvider, nodeKey, forkIdManager, natService);
  }

  private static DigitalSignatureAlgorithm algorithmFor(final PublicKey publicKey) {
    return publicKey instanceof CompositePublicKey
        ? new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get()
        : SignatureAlgorithmFactory.getInstance();
  }

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
    return hybridKeyPair();
  }

  /**
   * The node id length follows the active DSA, so a classical node key needs a classical provider:
   * a hybrid one would reject its 64-byte id.
   */
  private static KeyPair useClassicalDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1));
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    return SignatureAlgorithmFactory.getInstance().generateKeyPair();
  }

  private static KeyPair hybridKeyPair() throws InvalidAlgorithmParameterException {
    return new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get().generateNodeKeyPair();
  }
}
