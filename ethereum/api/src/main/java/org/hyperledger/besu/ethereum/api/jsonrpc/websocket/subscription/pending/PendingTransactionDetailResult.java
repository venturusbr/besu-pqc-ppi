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
package org.hyperledger.besu.ethereum.api.jsonrpc.websocket.subscription.pending;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.JsonRpcResult;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.Quantity;
import org.hyperledger.besu.ethereum.core.Transaction;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({
  "from",
  "gas",
  "gasPrice",
  "hash",
  "input",
  "nonce",
  "to",
  "type",
  "value",
  "yParity",
  "v",
  "r",
  "s",
  "publicKey",
  "signature",
  "dsaType"
})
public class PendingTransactionDetailResult implements JsonRpcResult {
  private final String from;
  private final String gas;
  private final String gasPrice;
  private final String hash;
  private final String input;
  private final String nonce;
  private final String to;
  private final String dsaType;
  private final String type;
  private final String value;
  private final String yParity;
  private final String publicKey;
  private final String signature;
  private final String v;
  private final String r;
  private final String s;

  public PendingTransactionDetailResult(final Transaction tx) {
    TransactionType transactionType = tx.getType();
    this.from = tx.getSender().toString();
    this.gas = Quantity.create(tx.getGasLimit());
    this.gasPrice = tx.getGasPrice().map(Quantity::create).orElse(null);
    this.hash = tx.getHash().toString();
    this.input = tx.getPayload().toString();
    this.nonce = Quantity.create(tx.getNonce());
    this.to = tx.getTo().map(a -> a.getBytes().toHexString()).orElse(null);
    if (transactionType == TransactionType.FRONTIER) {
      this.type = Quantity.create(0);
      this.yParity = null;
      this.r = Quantity.create(tx.getR());
      this.s = Quantity.create(tx.getS());
      this.v = Quantity.create(tx.getV());
      this.dsaType = null;
      this.publicKey = null;
      this.signature = null;
    } else if(isFlexible(transactionType)){
      this.type = Quantity.create(transactionType.getSerializedType());
      this.yParity = null;
      this.r = null;
      this.s = null;
      this.v = null;
      this.dsaType = String.format("0x%04X", tx.getDsaType().get() & 0xFFFF);
      // A flexible transaction whose key is recovered from its signature carries none.
      this.publicKey =
          tx.getMaybePublicKey().map(pk -> Bytes.wrap(pk.getEncoded()).toHexString()).orElse(null);
      this.signature = tx.getSignature().encodedBytes().toHexString();
    } else {
      this.type = Quantity.create(transactionType.getSerializedType());
      this.yParity = Quantity.create(tx.getYParity());
      this.v =
          (transactionType == TransactionType.ACCESS_LIST
                  || transactionType == TransactionType.EIP1559)
              ? Quantity.create(tx.getYParity())
              : null;
      this.r = Quantity.create(tx.getR());
      this.s = Quantity.create(tx.getS());
      this.dsaType = null;
      this.publicKey = null;
      this.signature = null;
    }
    this.value = Quantity.create(tx.getValue());
  }

  private Boolean isFlexible(final TransactionType txType){
    return txType == TransactionType.FLEXIBLE_ACCESS_LIST ||
      txType == TransactionType.FLEXIBLE_EIP1559 ||
      txType == TransactionType.FLEXIBLE_BLOB ||
      txType == TransactionType.FLEXIBLE_DELEGATE_CODE;
  }

  @JsonGetter(value = "from")
  public String getFrom() {
    return from;
  }

  @JsonGetter(value = "gas")
  public String getGas() {
    return gas;
  }

  @JsonGetter(value = "gasPrice")
  public String getGasPrice() {
    return gasPrice;
  }

  @JsonGetter(value = "hash")
  public String getHash() {
    return hash;
  }

  @JsonGetter(value = "input")
  public String getInput() {
    return input;
  }

  @JsonGetter(value = "nonce")
  public String getNonce() {
    return nonce;
  }

  @JsonGetter(value = "to")
  public String getTo() {
    return to;
  }

  @JsonGetter(value = "type")
  public String getType() {
    return type;
  }

  @JsonGetter(value = "value")
  public String getValue() {
    return value;
  }

  @JsonGetter(value = "publicKey")
  public String getPublicKey() {
    return publicKey;
  }

  @JsonGetter(value = "dsaType")
  public String getDsaType(){
    return dsaType;
  }

  @JsonGetter(value = "signature")
  public String getSignature(){
    return signature;
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  @JsonGetter(value = "yParity")
  public String getyParity() {
    return yParity;
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  @JsonGetter(value = "v")
  public String getV() {
    return v;
  }

  @JsonGetter(value = "r")
  public String getR() {
    return r;
  }

  @JsonGetter(value = "s")
  public String getS() {
    return s;
  }
}
