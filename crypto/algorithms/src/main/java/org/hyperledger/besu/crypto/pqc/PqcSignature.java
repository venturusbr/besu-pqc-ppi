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
package org.hyperledger.besu.crypto.pqc;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.SecureRandomProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class PqcSignature {

  private static final Logger LOG = LoggerFactory.getLogger(PqcSignature.class);

  private byte[] encoded;

  private void setSignature(final byte[] signature) {
    this.encoded = signature;
  }
  ;

  protected abstract String getSignatureName();

  public void create(final byte[] dataToSign, final PrivateKey privateKey) {
    checkNotNull(privateKey);
    checkNotNull(dataToSign);
    try {
      Signature sig = Signature.getInstance(getSignatureName(), "BCPQC");
      sig.initSign(privateKey, SecureRandomProvider.createSecureRandom());
      sig.update(dataToSign, 0, dataToSign.length);
      byte[] signature = sig.sign();
      setSignature(signature);
    } catch (NoSuchProviderException
        | NoSuchAlgorithmException
        | InvalidKeyException
        | SignatureException e) {
      LOG.info(e.getMessage());
    }
  }

  public byte[] getEncoded() {
    return encoded;
  }
}
