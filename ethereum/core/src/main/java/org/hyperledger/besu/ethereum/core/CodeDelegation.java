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
package org.hyperledger.besu.ethereum.core;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Optional;
import java.util.function.Supplier;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.providers.VerifierProvider;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.core.encoding.CodeDelegationEncoder;
import org.hyperledger.besu.ethereum.core.json.ChainIdDeserializer;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyDecoder;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.common.base.Suppliers;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
// ignore `signer` field used in execution-spec-tests
@JsonIgnoreProperties(ignoreUnknown = true)
public class CodeDelegation implements org.hyperledger.besu.datatypes.CodeDelegation {
  private static final Supplier<SignatureAlgorithm> SIGNATURE_ALGORITHM = Suppliers
      .memoize(SignatureAlgorithmFactory::getInstance);

  public static final Bytes MAGIC = Bytes.fromHexString("05");

  private volatile Bytes32 hashNoSignature;
  private final CodeDelegationType authorizationType;
  private final Optional<Short> dsaType;
  private final BigInteger chainId;
  private final Address address;
  private final long nonce;
  private final Signature signature;
  private final Optional<PublicKey> maybePublicKey;
  private final Supplier<Optional<Address>> authorizerSupplier = Suppliers.memoize(this::computeAuthority);

  /**
   * An access list entry as defined in EIP-7702
   *
   * @param chainId   can be either the current chain id or zero
   * @param address   the address from which the code will be set into the EOA
   *                  account
   * @param nonce     the nonce after which this auth expires
   * @param signature the signature of the EOA account which will be used to set
   *                  the code
   */
  public CodeDelegation(
      final BigInteger chainId,
      final Address address,
      final long nonce,
      final Signature signature) {
    this.authorizationType = CodeDelegationType.LEGACY;
    this.dsaType = Optional.empty();
    this.chainId = chainId; 
    this.address = address;
    this.maybePublicKey = Optional.empty();
    this.nonce = nonce;
    this.signature = signature;
  }

  public CodeDelegation(
      final CodeDelegationType authorizationType,
      final Optional<Short> dsaType,
      final BigInteger chainId,
      final Address address,
      final long nonce,
      final Optional<PublicKey> maybePublicKey,
      final Signature signature) {
    this.authorizationType = authorizationType;
    this.dsaType = dsaType;
    this.chainId = chainId;
    this.address = address;
    this.nonce = nonce;
    this.maybePublicKey = maybePublicKey;
    this.signature = signature;
  }

  /**
   * Create code delegation.
   *
   * @param chainId can be either the current chain id or zero
   * @param address the address from which the code will be set into the EOA
   *                account
   * @param nonce   the nonce
   * @param v       the recovery id
   * @param r       the r value of the signature
   * @param s       the s value of the signature
   * @return CodeDelegation
   */
  @JsonCreator
  public static org.hyperledger.besu.datatypes.CodeDelegation createCodeDelegation(
      @JsonProperty("type") final CodeDelegationType type,
      @JsonProperty("dsaType") final Short dsaType,
      @JsonProperty("chainId") @JsonDeserialize(using = ChainIdDeserializer.class) final BigInteger chainId,
      @JsonProperty("address") final Address address,
      @JsonProperty("nonce") final String nonce,
      @JsonProperty("maybePublicKey") final Bytes maybePublicKey,
      @JsonProperty("signature") final Bytes signature,
      @JsonProperty("v") final String v,
      @JsonProperty("r") final String r,
      @JsonProperty("s") final String s) {

    final long parsedNonce = Bytes.fromHexStringLenient(nonce).toLong();
    final CodeDelegationType effectiveType =
    type != null ? type : CodeDelegationType.LEGACY;

    switch (effectiveType) {
      case LEGACY:
        return createLegacy(chainId, address, parsedNonce, v, r, s);

      case FLEXIBLE:
        return createFlexible(dsaType, chainId, address, parsedNonce, maybePublicKey, signature);

      default:
        throw new IllegalArgumentException("Unsupported CodeDelegation type: " + type);
    }
  }

  private static CodeDelegation createLegacy(
    final BigInteger chainId,
    final Address address,
    final long nonce,
    final String v,
    final String r,
    final String s) {
    final Signature sig =
        SIGNATURE_ALGORITHM.get().createCodeDelegationSignature(
            Bytes.fromHexStringLenient(r).toUnsignedBigInteger(),
            Bytes.fromHexStringLenient(s).toUnsignedBigInteger(),
            Bytes.fromHexStringLenient(v).get(0));

    return new CodeDelegation(chainId, address, nonce, sig);
  }

  private static CodeDelegation createFlexible(
    final Short dsaType,
    final BigInteger chainId,
    final Address address,
    final long nonce,
    final Bytes maybePublicKey,
    final Bytes signature) {

    if (dsaType == null) {
      throw new IllegalArgumentException("dsaType is required for FLEXIBLE");
    }

    final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType);

    final Signature sig =
        SignatureFactory.createSignatureFromBytes(signature, dsaParams);

    // Same rules as a code delegation decoded from RLP: only the halves that cannot be recovered
    // may be provided, so a stated recoverable half is never taken on trust.
    final Optional<PublicKey> maybePk =
        maybePublicKey != null
            ? PublicKeyDecoder.fromProvidedBytes(enabledDsa(dsaType), maybePublicKey)
            : Optional.empty();

    return new CodeDelegation(
        CodeDelegationType.FLEXIBLE,
        Optional.of(dsaType),
        chainId,
        address,
        nonce,
        maybePk,
        sig);
  }

  private static DigitalSignatureAlgorithm enabledDsa(final Short dsaType) {
    final VerifierProvider verifierProvider = DSAProviderFactory.getVerifierProvider();
    final DigitalSignatureAlgorithm dsa =
        verifierProvider != null ? verifierProvider.getAccountEnabledDSAById(dsaType) : null;
    if (dsa == null) {
      throw new IllegalArgumentException("DSA type " + dsaType + " is not enabled");
    }
    return dsa;
  }

  @JsonProperty("type")
  @Override
  public CodeDelegationType getType() {
    return authorizationType;
  }

  @JsonProperty("dsaType")
  @Override
  public Optional<Short> dsaType() {
    return dsaType;
  }

  @JsonProperty("chainId")
  @Override
  public BigInteger chainId() {
    return chainId;
  }

  @JsonProperty("address")
  @Override
  public Address address() {
    return address;
  }

  @JsonProperty("maybePublicKey")
  @Override
  public Optional<PublicKey> maybePublicKey() {
    return maybePublicKey;
  }
  
  @Override
  public Optional<String> publicKey(){
    // A delegation that relies on public key recovery carries no key of its own, and recovering
    // one needs the signing hash this object does not hold, so there is nothing to report.
    return maybePublicKey.map(pk -> Bytes.wrap(pk.getEncoded()).toHexString());
  }

  @JsonProperty("signature")
  @Override
  public Signature signature() {
    return signature;
  }

  @Override
  public Optional<Address> authorizer() {
    // recId needs to be between either 0 or 1, otherwise the signature is invalid
    // which means we can't recover the authorizer.
    if (signature instanceof SECPSignature secp) {
      if (secp.getRecId() < 0 || secp.getRecId() > 1) {
        return Optional.empty();
      }
    }

    return authorizerSupplier.get();
  }

  @Override
  public long nonce() {
    return nonce;
  }

  @JsonProperty("v")
  @Override
  public byte v() {
    if (!(signature instanceof SECPSignature secp)) {
      throw new IllegalStateException("Expected SECPSignature");
    }
    return secp.getRecId();
  }

  @JsonProperty("r")
  @Override
  public BigInteger r() {
    if (!(signature instanceof SECPSignature secp)) {
      throw new IllegalStateException("Expected SECPSignature");
    }
    return secp.getR();
  }

  @JsonProperty("s")
  @Override
  public BigInteger s() {
    if (!(signature instanceof SECPSignature secp)) {
      throw new IllegalStateException("Expected SECPSignature");
    }
    return secp.getS();
  }

  private Optional<Address> computeAuthority() {
    Bytes32 hashToRecovery = getOrComputeSenderRecoveryHash();

    Optional<Address> authorityAddress;
    try {
      return switch (authorizationType) {
        case LEGACY -> computeLegacyAuthority(hashToRecovery);
        case FLEXIBLE -> computeFlexibleAuthority(hashToRecovery);
      };
    } catch (final IllegalArgumentException e) {
      authorityAddress = Optional.empty();
    }

    return authorityAddress;
  }

  private Optional<Address> computeLegacyAuthority(final Bytes32 hash) {
    if (!(signature instanceof SECPSignature)) {
      return Optional.empty();
    }

    final Optional<PublicKey> maybeRecovered = PublicKeyHandler.resolvePublicKey(
        SIGNATURE_ALGORITHM.get(),
        signature,
        maybePublicKey,
        hash
      );

    return maybeRecovered.map(
      pk -> Address.extract(
        Bytes32.wrap(
            Hash.hash(Bytes.wrap(pk.getEncoded())).getBytes()
        )
      )
    );
  }

  private Optional<Address> computeFlexibleAuthority(final Bytes32 hash) {
    if (dsaType.isEmpty()) {
      throw new IllegalStateException("Missing dsaType for FLEXIBLE");
    }

    Optional<PublicKey> publicKey = PublicKeyHandler.resolvePublicKey(
        DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(dsaType.get()),
        signature,
        maybePublicKey,
        hash
    );

    return Optional.of(
        Address.extract(
            Bytes32.wrap(Hash.hash(Bytes.wrap(publicKey.get().getEncoded())).getBytes())
        )
    );
  }

  @Override
  public Bytes32 getOrComputeSenderRecoveryHash(){
    if(hashNoSignature == null){
      hashNoSignature = computeSenderRecoveryHash();
    }

    return hashNoSignature;
  }

  private Bytes32 computeSenderRecoveryHash(){
    BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();
    
    CodeDelegationEncoder.encodeWithoutSignature(this, rlpOutput);

    final Hash hash = Hash.hash(Bytes.concatenate(MAGIC, rlpOutput.encoded()));

    return Bytes32.wrap(hash.getBytes());
  }

  /**
   * Create a code delegation authorization with a builder.
   *
   * @return CodeDelegation.Builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder for CodeDelegation authorizations. */
  public static class Builder {
    private CodeDelegationType authorizationType;
    private Short dsaType;
    private BigInteger chainId = BigInteger.ZERO;
    private Address address;
    private Long nonce;
    private PublicKey publicKey;
    private Signature signature;

    /** Create a new builder. */
    protected Builder() {
    }

    public Builder type(final CodeDelegationType authorizationType){
      this.authorizationType = authorizationType;
      return this;
    }

    public Builder dsaType(final Short dsaType) {
      this.dsaType = dsaType;
      return this;
    }

    /**
     * Set the optional chain id.
     *
     * @param chainId the chain id
     * @return this builder
     */
    public Builder chainId(final BigInteger chainId) {
      this.chainId = chainId;
      return this;
    }

    /**
     * Set the address of the authorized smart contract.
     *
     * @param address the address
     * @return this builder
     */
    public Builder address(final Address address) {
      this.address = address;
      return this;
    }

    /**
     * Set the nonce.
     *
     * @param nonce the nonce.
     * @return this builder
     */
    public Builder nonce(final long nonce) {
      this.nonce = nonce;
      return this;
    }

    public Builder publicKey(final PublicKey publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    /**
     * Set the signature of the authorizer account.
     *
     * @param signature the signature
     * @return this builder
     */
    public Builder signature(final Signature signature) {
      this.signature = signature;
      return this;
    }

    /**
     * Sign the authorization with the given key pair and return the authorization.
     *
     * @param keyPair the key pair
     * @return CodeDelegation
     */
    public org.hyperledger.besu.datatypes.CodeDelegation signAndBuild(final KeyPair keyPair) {
      final BytesValueRLPOutput output = new BytesValueRLPOutput();

      // change: serialize by authorityType
      output.startList();
      output.writeBigIntegerScalar(chainId);
      output.writeBytes(address.getBytes());
      output.writeLongScalar(nonce);
      output.endList();

      signature(
          SIGNATURE_ALGORITHM
              .get()
              .sign(
                  Bytes32.wrap(Hash.hash(Bytes.concatenate(MAGIC, output.encoded())).getBytes()),
                  keyPair));
      return build();
    }

    /**
     * Build the authorization.
     *
     * @return CodeDelegation
     */
    public org.hyperledger.besu.datatypes.CodeDelegation build() {
      if (address == null) {
        throw new IllegalStateException("Address must be set");
      }

      if (nonce == null) {
        throw new IllegalStateException("Nonce must be set");
      }

      if (signature == null) {
        throw new IllegalStateException("Signature must be set");
      }

      return new CodeDelegation(
        authorizationType, 
        Optional.ofNullable(dsaType), 
        chainId, 
        address, 
        nonce, 
        Optional.ofNullable(publicKey), 
        signature);
    }
  }

  @Override
  public String toString() {
    return "CodeDelegation{"
        + "type"
        + authorizationType
        + "dsaType="
        + dsaType
        + "chainId="
        + chainId
        + ", address="
        + address
        + ", nonce="
        + nonce
        + ", publicKey="
        + maybePublicKey
        + ", signature="
        + signature
        + ", authorizerSupplier="
        + authorizerSupplier
        + '}';
  }
}
