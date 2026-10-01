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

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.signature.Signature;

import java.math.BigInteger;

import com.google.common.base.Strings;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * The encoder no longer knows how any particular algorithm is laid out: each signature encodes
 * itself, which is what lets a hybrid one travel whole instead of being cut down to 65 bytes.
 */
public class PacketSignatureEncoderTest {

  private PacketSignatureEncoder packetSignatureEncoder;

  @BeforeEach
  public void beforeTest() {
    packetSignatureEncoder = new PacketSignatureEncoder();
  }

  @Test
  public void defersToTheSignatureForItsEncoding() {
    final Signature signature = Mockito.mock(Signature.class);
    final Bytes encoded = Bytes.repeat((byte) 0x07, 2485);
    Mockito.when(signature.encodedBytes()).thenReturn(encoded);

    assertThat(packetSignatureEncoder.encodeSignature(signature)).isEqualTo(encoded);
    Mockito.verify(signature).encodedBytes();
  }

  @Test
  @SuppressWarnings("InlineMeInliner")
  public void aClassicalSignatureStillEncodesToRSV() {
    final SECPSignature signature =
        SignatureAlgorithmFactory.getInstance()
            .createSignature(
                new BigInteger(1, Bytes.repeat((byte) 0x01, 32).toArray()),
                new BigInteger(1, Bytes.repeat((byte) 0x02, 32).toArray()),
                (byte) 0x01);

    assertThat(packetSignatureEncoder.encodeSignature(signature).toHexString())
        .isEqualTo("0x" + Strings.repeat("01", 32) + Strings.repeat("02", 32) + "01");
  }
}
