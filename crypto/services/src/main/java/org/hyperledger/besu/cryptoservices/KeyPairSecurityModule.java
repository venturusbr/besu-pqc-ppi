/*
 * Copyright ConsenSys AG.
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
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcSignature;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.PqcSignatureFactory;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.AbstractCrystalsDilithium3;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.CrystalsDilithiumSignature;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.falcon.Falcon;
import org.hyperledger.besu.crypto.pqc.falcon.FalconSignature;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconKeyPair;
import org.hyperledger.besu.crypto.pqc.metrics.CSVWriter;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlus;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlusSignature;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusKeyPair;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.spec.ECPoint;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Implementation of SecurityModule wrapping SECP256K1.KeyPair and performing cryptographic
 * operations via SECP256K1 class
 */
public class KeyPairSecurityModule implements SecurityModule {
  private final KeyPair keyPair;
  private final Dilithium3KeyPair pqcKeyPair;
  private final SphincsPlusKeyPair sphincsKeyPair;
  private final FalconKeyPair falconKeyPair;
  private final PublicKey publicKey;
  private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
  private final PqcSignatureAlgorithm pqcSignatureAlgorithm = SignatureAlgorithmFactory.getPqcGenericInstance("Dilithium");
  private final AbstractCrystalsDilithium3 dilithiumSignatureAlgorithm = SignatureAlgorithmFactory.getPQCInstance();
  private final SphincsPlus sphincsSignatureAlgorithm = SignatureAlgorithmFactory.getSphincsPlusInstance();
  private final Falcon falconSignatureAlgorithm = SignatureAlgorithmFactory.getFalconInstance();
  private final CSVWriter csvWriter;

  /**
   * Instantiates a new Key pair security module.
   *
   * @param keyPair the key pair
   */
  public KeyPairSecurityModule(final KeyPair keyPair, final Dilithium3KeyPair pqcKeyPair, final SphincsPlusKeyPair sphincsPair, final FalconKeyPair falconPair) {
    this.keyPair = keyPair;
    this.pqcKeyPair = pqcKeyPair;
    this.sphincsKeyPair = sphincsPair;
    this.falconKeyPair = falconPair;
    this.publicKey = convertPublicKey(keyPair.getPublicKey());
    this.csvWriter = CSVWriter.getInstance();
  }

  private PublicKey convertPublicKey(final SECPPublicKey publicKey) {
    try {
      return new PublicKeyImpl(
          ECPointUtil.fromBouncyCastleECPoint(signatureAlgorithm.publicKeyAsEcPoint(publicKey)));
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Unexpected error while converting ECPoint: " + e.getMessage(), e);
    }
  }

  @Override
  public Signature sign(final Bytes32 dataHash) throws SecurityModuleException {
    try {
      long startSecpSign = System.nanoTime();
      final SECPSignature signature = signatureAlgorithm.sign(dataHash, keyPair);
      long endSecpSign = System.nanoTime();
      
      byte[] secpSignatureEncoded = signature.encodedBytes().toArray();
      PrivateKey dilithiumPrivateKey = pqcKeyPair.getPrivateKey().getCrystalsDilithiumPrivateKeyFromEncoded();
      long startDilithiumSign = System.nanoTime();

      //colocar o valor capturado pela flag na linha 59
      final PqcSignature pqcSignature = PqcSignatureFactory.createSignature(dilithiumPrivateKey, secpSignatureEncoded, pqcSignatureAlgorithm.getAlgorithmName());
      
      final CrystalsDilithiumSignature dilithiumSignature = dilithiumSignatureAlgorithm.sign(secpSignatureEncoded, dilithiumPrivateKey);
      long endDilithiumSign = System.nanoTime();
      
      byte[] secpSignatureEncodedforSphincs = signature.encodedBytes().toArray();
      PrivateKey sphincsPrivateKey = sphincsKeyPair.getPrivateKey().getSphincsPlusPrivateKeyFromEncoded();
      long startSphincsSign = System.nanoTime();
      final SphincsPlusSignature sphincsSignature = sphincsSignatureAlgorithm.sign(secpSignatureEncodedforSphincs, sphincsPrivateKey);
      long endSphincsSign = System.nanoTime();

      byte[] secpSignatureEncodedforFalcon = signature.encodedBytes().toArray();
      PrivateKey falconPrivateKey = falconKeyPair.getPrivateKey().getFalconPrivateKeyFromEncoded();
      long startFalconSign = System.nanoTime();
      final FalconSignature falconSignature = falconSignatureAlgorithm.sign(secpSignatureEncodedforFalcon, falconPrivateKey);
      long endFalconSign = System.nanoTime();

      long secpTime = endSecpSign - startSecpSign;
      long dilithiumTime = endDilithiumSign - startDilithiumSign;
      long sphincsTime = endSphincsSign - startSphincsSign;
      long falconTime = endFalconSign - startFalconSign;
      
      long secpAndDilithiumTime = secpTime + dilithiumTime;
      long secpAndSphincsTime = secpTime + sphincsTime;
      long secpAndFalconTime = secpTime + falconTime; 

      csvWriter.write(secpTime, secpAndDilithiumTime, dilithiumSignature, secpAndSphincsTime, sphincsSignature, secpAndFalconTime, falconSignature);

      return new SignatureImpl(signature);
    } catch (final Exception e) {
      throw new SecurityModuleException("Unexpected error while signing: " + e.getMessage(), e);
    }
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    return publicKey;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey)
      throws SecurityModuleException {
    try {
      final Bytes encodedECPoint = ECPointUtil.getEncodedBytes(partyKey.getW());
      final SECPPublicKey secp256KPartyKey = signatureAlgorithm.createPublicKey(encodedECPoint);
      return signatureAlgorithm.calculateECDHKeyAgreement(
          keyPair.getPrivateKey(), secp256KPartyKey);
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Unexpected error while calculating ECDH Key Agreement: " + e.getMessage(), e);
    }
  }

  private static class SignatureImpl implements Signature {

    private final SECPSignature signature;

    /**
     * Instantiates a new Signature.
     *
     * @param signature the signature
     */
    SignatureImpl(final SECPSignature signature) {
      this.signature = signature;
    }

    @Override
    public BigInteger getR() {
      return signature.getR();
    }

    @Override
    public BigInteger getS() {
      return signature.getS();
    }
  }

  private static class PublicKeyImpl implements PublicKey {
    private final ECPoint w;

    /**
     * Instantiates a new Public key.
     *
     * @param w the w ECPoint
     */
    PublicKeyImpl(final ECPoint w) {
      this.w = w;
    }

    @Override
    public ECPoint getW() {
      return w;
    }
  }
}
