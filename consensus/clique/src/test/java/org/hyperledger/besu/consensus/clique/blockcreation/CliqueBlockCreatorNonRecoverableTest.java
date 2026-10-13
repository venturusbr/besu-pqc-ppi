/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.consensus.clique.blockcreation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.ethereum.core.InMemoryKeyValueStorageProvider.createInMemoryBlockchain;
import static org.hyperledger.besu.ethereum.core.InMemoryKeyValueStorageProvider.createInMemoryWorldStateArchive;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.config.GenesisConfig;
import org.hyperledger.besu.consensus.clique.CliqueBlockHeaderFunctions;
import org.hyperledger.besu.consensus.clique.CliqueBlockInterface;
import org.hyperledger.besu.consensus.clique.CliqueContext;
import org.hyperledger.besu.consensus.clique.CliqueExtraData;
import org.hyperledger.besu.consensus.clique.CliqueHelpers;
import org.hyperledger.besu.consensus.clique.CliqueProtocolSchedule;
import org.hyperledger.besu.consensus.clique.TestHelpers;
import org.hyperledger.besu.consensus.common.EpochManager;
import org.hyperledger.besu.consensus.common.ForksSchedule;
import org.hyperledger.besu.consensus.common.validator.ValidatorProvider;
import org.hyperledger.besu.consensus.common.validator.VoteProvider;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.providers.NodeKeyProvider;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.chain.BadBlockManager;
import org.hyperledger.besu.ethereum.chain.GenesisState;
import org.hyperledger.besu.ethereum.chain.MutableBlockchain;
import org.hyperledger.besu.ethereum.core.AddressHelpers;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockBody;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderTestFixture;
import org.hyperledger.besu.ethereum.core.ImmutableMiningConfiguration;
import org.hyperledger.besu.ethereum.core.ImmutableMiningConfiguration.MutableInitValues;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.eth.manager.EthContext;
import org.hyperledger.besu.ethereum.eth.manager.EthScheduler;
import org.hyperledger.besu.ethereum.eth.transactions.BlobCache;
import org.hyperledger.besu.ethereum.eth.transactions.ImmutableTransactionPoolConfiguration;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionBroadcaster;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPoolConfiguration;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPoolMetrics;
import org.hyperledger.besu.ethereum.eth.transactions.sorter.GasPricePendingTransactionsSorter;
import org.hyperledger.besu.ethereum.mainnet.BalConfiguration;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.cache.CodeCache;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;
import org.hyperledger.besu.testutil.DeterministicEthScheduler;
import org.hyperledger.besu.testutil.TestClock;

import java.security.PublicKey;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.Lists;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Blocks created by a node whose key cannot be recovered from its signatures. The created header
 * must carry the proposer's public key so other nodes can attribute it, and so it can be read back
 * from its raw bytes.
 */
class CliqueBlockCreatorNonRecoverableTest {

  private final EthScheduler ethScheduler = new DeterministicEthScheduler();
  private final NoOpMetricsSystem metricsSystem = new NoOpMetricsSystem();

  private DigitalSignatureAlgorithm dsa;
  private MutableBlockchain blockchain;
  private ProtocolContext protocolContext;
  private ProtocolSchedule protocolSchedule;

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"SECP256K1", "MLDSA44", "FALCON512", "SECP256K1MLDSA44", "SECP256K1FALCON512"})
  void createdBlockIsAttributedToItsProposer(final DSAParametersSet params) throws Exception {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.setNodeActiveDSA(params.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    dsa = DSAProviderFactory.getActiveDSA();

    final KeyPair proposerKeyPair = dsa.generateNodeKeyPair();
    final KeyPair otherKeyPair = dsa.generateNodeKeyPair();
    final NodeKey proposerNodeKey = nodeKeyFor(proposerKeyPair);
    final Address proposerAddress = Address.extract(proposerKeyPair.getPublicKey());
    final List<Address> validators =
        Lists.newArrayList(proposerAddress, Address.extract(otherKeyPair.getPublicKey()));
    setUpChain(proposerNodeKey, validators, otherKeyPair);

    final Bytes extraData =
        CliqueExtraData.createWithoutProposerSeal(Bytes.wrap(new byte[32]), validators);
    final CliqueBlockCreator blockCreator =
        new CliqueBlockCreator(
            createMiningConfiguration(extraData, AddressHelpers.ofValue(1)),
            parent -> extraData,
            createTransactionPool(),
            protocolContext,
            protocolSchedule,
            proposerNodeKey,
            new EpochManager(10),
            ethScheduler);

    final BlockHeader created =
        blockCreator.createBlock(5L, blockchain.getChainHeadHeader()).getBlock().getHeader();

    assertThat(CliqueHelpers.getProposerOfBlock(created)).isEqualTo(proposerAddress);
    // As another node would see it: parsed again from the raw header bytes.
    final BlockHeader received =
        BlockHeader.readFrom(
            RLP.input(RLP.encode(created::writeTo)), new CliqueBlockHeaderFunctions());
    assertThat(CliqueExtraData.decode(received).getProposerAddress()).isEqualTo(proposerAddress);
  }

  private void setUpChain(
      final NodeKey proposerNodeKey, final List<Address> validators, final KeyPair otherKeyPair) {
    final ValidatorProvider validatorProvider = mock(ValidatorProvider.class);
    final VoteProvider voteProvider = mock(VoteProvider.class);
    when(validatorProvider.getVoteProviderAtHead()).thenReturn(Optional.of(voteProvider));
    when(validatorProvider.getValidatorsAfterBlock(any())).thenReturn(validators);

    protocolSchedule =
        CliqueProtocolSchedule.create(
            GenesisConfig.DEFAULT.getConfigOptions(),
            new ForksSchedule<>(List.of()),
            proposerNodeKey,
            false,
            EvmConfiguration.DEFAULT,
            MiningConfiguration.MINING_DISABLED,
            new BadBlockManager(),
            false,
            BalConfiguration.DEFAULT,
            metricsSystem);

    final CliqueContext cliqueContext =
        new CliqueContext(validatorProvider, null, new CliqueBlockInterface());
    CliqueHelpers.setCliqueContext(cliqueContext);

    final Block genesis =
        GenesisState.fromConfig(GenesisConfig.mainnet(), protocolSchedule, new CodeCache())
            .getBlock();
    blockchain = createInMemoryBlockchain(genesis);
    protocolContext =
        new ProtocolContext.Builder()
            .withBlockchain(blockchain)
            .withWorldStateArchive(createInMemoryWorldStateArchive())
            .withConsensusContext(cliqueContext)
            .build();

    // A block above genesis, sealed by the other validator.
    final BlockHeaderTestFixture headerTestFixture = new BlockHeaderTestFixture();
    headerTestFixture.number(1).parentHash(genesis.getHeader().getHash());
    blockchain.appendBlock(
        new Block(
            TestHelpers.createSealedBlockHeader(
                headerTestFixture, validators, otherKeyPair, otherKeyPair),
            new BlockBody(Lists.newArrayList(), Lists.newArrayList())),
        Lists.newArrayList());
  }

  private NodeKey nodeKeyFor(final KeyPair keyPair) {
    return new NodeKey(
        new NodeKeyProvider() {
          @Override
          public Signature sign(final Bytes32 data) {
            return dsa.sign(data, keyPair.getPrivateKey());
          }

          @Override
          public PublicKey getPublicKey() {
            return keyPair.getPublicKey();
          }

          @Override
          public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
            throw new UnsupportedOperationException();
          }
        });
  }

  private TransactionPool createTransactionPool() {
    final TransactionPoolConfiguration conf =
        ImmutableTransactionPoolConfiguration.builder().txPoolMaxSize(5).build();
    final EthContext ethContext = mock(EthContext.class, RETURNS_DEEP_STUBS);
    when(ethContext.getEthPeers().subscribeConnect(any())).thenReturn(1L);
    final TransactionPool transactionPool =
        new TransactionPool(
            () ->
                new GasPricePendingTransactionsSorter(
                    conf,
                    TestClock.system(ZoneId.systemDefault()),
                    metricsSystem,
                    blockchain::getChainHeadHeader),
            protocolSchedule,
            protocolContext,
            mock(TransactionBroadcaster.class),
            ethContext,
            new TransactionPoolMetrics(metricsSystem),
            conf,
            new BlobCache());
    transactionPool.setEnabled();
    return transactionPool;
  }

  private static MiningConfiguration createMiningConfiguration(
      final Bytes extraData, final Address coinbase) {
    return ImmutableMiningConfiguration.builder()
        .mutableInitValues(
            MutableInitValues.builder()
                .extraData(extraData)
                .targetGasLimit(10_000_000L)
                .minTransactionGasPrice(Wei.ZERO)
                .coinbase(coinbase)
                .build())
        .build();
  }
}
