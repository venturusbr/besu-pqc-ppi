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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.results;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.datatypes.CodeDelegation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.apache.tuweni.units.bigints.UInt256;

@JsonPropertyOrder({"type","dsaType","chainId", "address", "nonce", "yParity", "r", "s", "publicKey", "signature"})
public class CodeDelegationResult {
  private final String type;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String dsaType;
  private final String chainId;
  private final String address;
  private final String nonce;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String yParity;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String r;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String s;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String publicKey;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private final String signature;

  public CodeDelegationResult(final CodeDelegation codeDelegation) {
    type = Quantity.create(codeDelegation.getType().getSerializedType());
    // A legacy delegation carries no DSA type, so the field is left out of the response
    // rather than reported as null.
    dsaType = codeDelegation.dsaType().map(String::valueOf).orElse(null);
    chainId = Quantity.create(UInt256.valueOf(codeDelegation.chainId()));
    address = codeDelegation.address().getBytes().toHexString();
    nonce = Quantity.create(codeDelegation.nonce());
    // yParity, r and s only exist for a secp256k1 signature; any other signature (ML-DSA or a
    // hybrid one) is reported whole in "signature", and these fields are left out.
    if (codeDelegation.signature() instanceof SECPSignature) {
      yParity = Quantity.create(codeDelegation.v());
      r = Quantity.create(codeDelegation.r());
      s = Quantity.create(codeDelegation.s());
    } else {
      yParity = null;
      r = null;
      s = null;
    }
    publicKey = codeDelegation.publicKey().orElse(null);
    signature = codeDelegation.signature().encodedBytes().toString();
  }

  @JsonProperty("type")
  public String type(){
    return type;
  }

  @JsonProperty("dsaType")
  public String dsaType(){
    return dsaType;
  }

  @JsonProperty("chainId")
  public String chainId() {
    return chainId;
  }

  @JsonProperty("address")
  public String address() {
    return address;
  }

  @JsonProperty("nonce")
  public String nonce() {
    return nonce;
  }

  @JsonProperty("yParity")
  public String yParity() {
    return yParity;
  }

  @JsonProperty("r")
  public String r() {
    return r;
  }

  @JsonProperty("s")
  public String s() {
    return s;
  }

  @JsonProperty("publicKey")
  public String publicKey(){
    return publicKey;
  }

  @JsonProperty("signature")
  public String signature(){
    return signature;
  }
}
