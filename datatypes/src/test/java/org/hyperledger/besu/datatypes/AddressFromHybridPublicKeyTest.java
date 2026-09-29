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
package org.hyperledger.besu.datatypes;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * An address is the tail of the keccak256 of a public key's encoding, and {@link
 * Address#extract(PublicKey)} now takes any public key rather than only a secp256k1 one. A hybrid
 * key encodes to different bytes than the secp256k1 key inside it, so it is a different identity.
 */
class AddressFromHybridPublicKeyTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  @Test
  void aHybridKeyAndItsClassicalHalfAreDifferentAddresses() {
    final CompositePublicKey hybridKey = hybridPublicKey();

    final Address hybridAddress = Address.extract(hybridKey);
    final Address classicalAddress = Address.extract(hybridKey.getFirstKey());

    // the same secp256k1 key controls both, yet the account they name is not the same
    assertThat(hybridAddress).isNotEqualTo(classicalAddress);
  }

  @Test
  void aHybridAddressHashesTheWholeKey() {
    final CompositePublicKey hybridKey = hybridPublicKey();
    final Bytes encoded = Bytes.wrap(hybridKey.getEncoded());
    assertThat(encoded.size()).isEqualTo(HYBRID.getPublicKeyLength());

    final Address address = Address.extract(hybridKey);

    assertThat(address).isEqualTo(Address.extract(Bytes32.wrap(Hash.keccak256(encoded))));
  }

  @Test
  void aClassicalAddressStillHashesTheSixtyFourByteKey() {
    final PublicKey secpKey =
        SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey();
    final Bytes encoded = Bytes.wrap(secpKey.getEncoded());
    assertThat(encoded.size()).isEqualTo(DSAParametersSet.SECP256K1.getPublicKeyLength());

    assertThat(Address.extract(secpKey))
        .isEqualTo(Address.extract(Bytes32.wrap(Hash.keccak256(encoded))));
  }

  @Test
  void theSameHybridKeyAlwaysGivesTheSameAddress() {
    final CompositePublicKey hybridKey = hybridPublicKey();

    // rebuilt from the encoding, as a node reads it back from its key file
    final CompositePublicKey rebuilt =
        CompositePublicKey.create(hybridKey.getFirstKey(), hybridKey.getSecondKey());

    assertThat(Address.extract(rebuilt)).isEqualTo(Address.extract(hybridKey));
  }

  @Test
  void differentHybridKeysGiveDifferentAddresses() {
    assertThat(Address.extract(hybridPublicKey())).isNotEqualTo(Address.extract(hybridPublicKey()));
  }

  @Test
  void anAddressIsTwentyBytesWhateverTheKeySize() {
    assertThat(Address.extract(hybridPublicKey()).getBytes().size()).isEqualTo(Address.SIZE);
    assertThat(
            Address.extract(
                    SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey())
                .getBytes()
                .size())
        .isEqualTo(Address.SIZE);
  }

  private static CompositePublicKey hybridPublicKey() {
    final DigitalSignatureAlgorithm algorithm =
        new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();
    final KeyPair keyPair = algorithm.generateNodeKeyPair();
    return (CompositePublicKey) keyPair.getPublicKey();
  }
}
