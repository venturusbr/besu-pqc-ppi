[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Motivation and design](01-motivation-and-design.md) · [Next: Cryptography →](03-cryptography/README.md)

---

# Architecture

## Contents

- [Module map](#module-map)
- [Component diagram](#component-diagram)
- [Node start-up](#node-start-up)
- [Transaction life cycle](#transaction-life-cycle)
- [Consensus message flow](#consensus-message-flow)
- [Main classes by module](#main-classes-by-module)

## Module map

The fork keeps Besu's module structure. These are the modules it changes:

| Module | Main changes |
|---|---|
| `crypto/algorithms` | The DSA abstraction, ML-DSA, Falcon, hybrids, key factories, providers, signature metrics, microbenchmark |
| `crypto/services` | `NodeKey` and `SecurityModuleAdapter` work with any DSA |
| `datatypes` | `TransactionType` flexible types, `CodeDelegationType`, `Address.extract(PublicKey)` |
| `ethereum/core` | Flexible transaction encoders and decoders, `Transaction` (dsaType, publicKey, sender resolution), `CodeDelegation`, `PublicKeyEncoder` / `PublicKeyDecoder`, `MainnetTransactionValidator`, `MainnetProtocolSpecs` (Prague) |
| `ethereum/eth` | Transaction pool memory accounting for large signatures |
| `ethereum/api` | `VNT` namespace, `vnt_getAccountsSupportedDSAs`, transaction and delegation result objects |
| `ethereum/p2p` | Node IDs of any length, discv4 packets with partial keys, `vnt` node records, ECDHE with the ECDSA half |
| `consensus/common`, `qbft`, `qbft-core`, `ibft`, `clique` | Signed messages carrying keys, commit seals with keys, Clique key-carrying `extraData`, integration tests per DSA |
| `app` | `--node-dsa`, `--accounts-supported-dsas`, DSA provider start-up, `operator generate-blockchain-config --node-dsa` |
| `settings.gradle`, `platform` | Source dependency on the forked discovery library, Bouncy Castle |

## Component diagram

```mermaid
flowchart TB
  subgraph app["app"]
    CLI["BesuCommand<br/>--node-dsa · --accounts-supported-dsas"]
    OP["operator generate-blockchain-config"]
  end
  subgraph crypto["crypto/algorithms"]
    FACT["DSAProviderFactory"]
    PROV["DigitalSignatureAlgorithmProvider<br/>(NodeKey · KeyManagement · Verifier)"]
    CONF["DigitalSignatureAlgorithmConfiguration<br/>node DSA · account DSAs"]
    ALG["SECP256K1 · SECP256R1 · MLDSA · Falcon<br/>HybridStrongNestingConcatenation"]
    PKH["PublicKeyHandler · KeyFactory · SignatureFactory"]
    MET["MetricWriters (CSV)"]
  end
  subgraph services["crypto/services"]
    NK["NodeKey / SecurityModuleAdapter"]
  end
  subgraph eth["ethereum"]
    CORE["core: Transaction · encoders · validator"]
    POOL["eth: TransactionPool"]
    API["api: JSON-RPC (ETH, VNT)"]
    P2P["p2p: discv4 · ENR · RLPx"]
  end
  subgraph cons["consensus"]
    BFT["QBFT · IBFT 2.0<br/>SignedData · CommitSeal"]
    CLQ["Clique<br/>CliqueExtraData"]
  end
  CLI --> FACT
  OP --> FACT
  FACT --> PROV
  PROV --> CONF --> ALG
  PROV --> NK
  CORE --> PKH
  CORE --> FACT
  API --> CORE
  API --> FACT
  POOL --> CORE
  BFT --> NK
  BFT --> PKH
  CLQ --> NK
  CLQ --> PKH
  P2P --> NK
  P2P --> PKH
  ALG --> MET
```

## Node start-up

```mermaid
sequenceDiagram
  participant U as Operator
  participant B as BesuCommand
  participant G as Genesis
  participant F as DSAProviderFactory
  participant K as Key loading
  U->>B: besu --node-dsa=SECP256K1-MLDSA44 --accounts-supported-dsas=...
  B->>G: read ecCurve (default secp256k1)
  B->>B: check that --node-dsa signs on the genesis curve
  B->>F: setDsaProvider(node DSA, account DSAs, key file)
  Note over F: log "Account-enabled DSAs: ..."
  alt node DSA is SECP256K1 / SECP256R1
    B->>K: SecurityModule (upstream behaviour)
  else hybrid / post-quantum
    B->>K: KeyManager.loadNodeKeyPair(--node-private-key-file)
  end
  B->>B: build the enode from the full public key, start P2P, consensus, RPC
```

## Transaction life cycle

```mermaid
sequenceDiagram
  participant W as Wallet
  participant R as JSON-RPC
  participant D as TransactionDecoder
  participant V as MainnetTransactionValidator
  participant P as TransactionPool
  participant B as Block producer / importer
  W->>R: eth_sendRawTransaction(0x42 ‖ rlp)
  R->>D: decode
  D->>D: dsaType → enabled DSA? (otherwise DsaNotEnabledException → -32602)
  D->>D: read publicKey (only the non-recoverable part)
  R->>P: add
  P->>V: validate: structure → resolve sender → verify
  V->>V: cache successful verification by tx hash
  P-->>W: tx hash
  B->>P: select transactions
  B->>V: validate again during block processing (cache hit)
  B->>B: execute, seal (node DSA), gossip
  Note over B: peers re-validate on import (their own cache)
```

## Consensus message flow

```mermaid
sequenceDiagram
  participant A as Validator A
  participant N as Network
  participant Bv as Validator B
  A->>A: sign payload with node key (hybrid)
  A->>N: RLP[payload, signature, pk_mldsa]
  N->>Bv: message
  Bv->>Bv: recover pk_ecdsa from σ₁
  Bv->>Bv: verify σ₂ with pk_mldsa
  Bv->>Bv: author = keccak256(pk_ecdsa ‖ pk_mldsa)[-20:]
  Bv->>Bv: check that the author is a validator
```

## Main classes by module

| Concern | Classes |
|---|---|
| Algorithm registry | `DSAParametersSet`, `SupportedAlgorithms` |
| Algorithms | `SECP256K1`, `SECP256R1`, `MLDSA`, `Falcon`, `HybridStrongNestingConcatenation` |
| Providers | `DSAProviderFactory`, `DigitalSignatureAlgorithmProvider`, `DigitalSignatureAlgorithmConfiguration` |
| Keys | `KeyFactory`, `KeyManager`, `KeyExtractor`, `CompositePublicKey`, `PublicKeyHandler` |
| Signatures | `Signature`, `SignatureFactory`, `CompositeSignature`, `MLDSASignature`, `FalconSignature`, `SignatureValidationContext` |
| Transactions | `TransactionType`, `Transaction`, `Flexible*TransactionEncoder` / `Decoder`, `PublicKeyEncoder` / `Decoder`, `CodeDelegation`, `MainnetTransactionValidator` |
| Consensus | `SignedData`, `CommitSeal`, `BftExtraDataCodec`, `CliqueExtraData`, `CliqueBlockHashing` |
| P2P | `EnodeURLImpl`, `Packet`, `PacketFactory`, `NodeRecordManager`, `EnrSignatureValidator` |
| RPC | `RpcApis.VNT`, `VntGetAccountsSupportedDSAs`, `TransactionCompleteResult`, `TransactionPendingResult`, `CodeDelegationResult` |
| CLI | `BesuCommand`, `NodeDsaCurve`, `DSAParametersSetConverter`, `GenerateBlockchainConfig` |

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Motivation and design](01-motivation-and-design.md) · [Next: Cryptography →](03-cryptography/README.md)
