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
package org.hyperledger.besu.cryptoservices;

import org.hyperledger.besu.crypto.ECPointUtil;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.providers.NodeKeyProvider;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes32;

public class SecurityModuleAdapter implements NodeKeyProvider {
  final SecurityModule securityModule;
  final SignatureAlgorithm ecdsa;
  SECPPublicKey pk;

  public SecurityModuleAdapter(final SecurityModule securityModule) {
    this.securityModule = securityModule;
    this.ecdsa = SignatureAlgorithmFactory.getInstance();
  }

  @Override
  public Signature sign(final Bytes32 dataHash) {
    org.hyperledger.besu.plugin.services.securitymodule.data.Signature ecdsaSignature =
        securityModule.sign(dataHash);

    return ecdsa.normaliseSignature(
        ecdsaSignature.getR(), ecdsaSignature.getS(), getSecpPublicKey(), dataHash);
  }

  @Override
  public PublicKey getPublicKey() {
    return getSecpPublicKey();
  }

  private SECPPublicKey getSecpPublicKey() {
    if (pk == null) {
      pk = ecdsa.createPublicKey(ECPointUtil.getEncodedBytes(securityModule.getPublicKey().getW()));
    }
    return pk;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
    SECPPublicKey ecdsaPartyKey = (SECPPublicKey) partyKey;
    return securityModule.calculateECDHKeyAgreement(
        () -> ECPointUtil.fromBouncyCastleECPoint(ecdsa.publicKeyAsEcPoint(ecdsaPartyKey)));
  }
}
