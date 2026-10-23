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
package org.hyperledger.besu.consensus.qbft.core.payload;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.qbft.core.types.QbftBlockCodec;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.cryptoservices.NodeKeyUtils;
import org.hyperledger.besu.datatypes.Hash;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * A QBFT message is named the same in the sign and the verify metrics, after the protocol and the
 * message, so the rows of both files can be matched.
 */
class QbftMetricsLabelTest {

  private static final ConsensusRoundIdentifier ROUND = new ConsensusRoundIdentifier(1, 0);

  @Test
  void eachMessageIsNamedAfterTheProtocolAndTheMessage() {
    final NodeKey nodeKey = NodeKeyUtils.generate();
    final CommitPayload commit =
        new CommitPayload(ROUND, Hash.ZERO, nodeKey.sign(Bytes32.ZERO, "test"));

    assertThat(new PreparePayload(ROUND, Hash.ZERO).getMetricsLabel()).isEqualTo("qbft-prepare");
    assertThat(commit.getMetricsLabel()).isEqualTo("qbft-commit");
    assertThat(new RoundChangePayload(ROUND, Optional.empty()).getMetricsLabel())
        .isEqualTo("qbft-round-change");
    assertThat(
            new RoundChangePayload(ROUND, Optional.of(new PreparedRoundMetadata(Hash.ZERO, 0)))
                .getMetricsLabel())
        .isEqualTo("qbft-round-change-prepared-block");
  }

  @Test
  void aMessageIsSignedUnderItsLabel() {
    final NodeKey nodeKey = spy(NodeKeyUtils.generate());
    final MessageFactory messageFactory = new MessageFactory(nodeKey, mock(QbftBlockCodec.class));

    messageFactory.createPrepare(ROUND, Hash.ZERO);
    messageFactory.createRoundChange(ROUND, Optional.empty());

    verify(nodeKey).sign(any(Bytes32.class), eq("qbft-prepare"));
    verify(nodeKey).sign(any(Bytes32.class), eq("qbft-round-change"));
  }
}
