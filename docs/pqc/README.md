**🏠 Index** · [⚡ Quick start](00-quick-start.md) · [Next: Quick start →](00-quick-start.md)

---

# Besu PQC: post-quantum signatures for Besu

**besu-pqc-ppi** is a experimental fork of [Besu](https://github.com/hyperledger/besu) 26.1.0. It makes the client
**agnostic to the digital signature algorithm (DSA)**. Transactions, code delegations, consensus messages, block seals
and discovery v4 packets can be signed with the post-quantum
algorithms **ML-DSA** (FIPS 204) and **Falcon-512**, with **hybrid** ECDSA + post-quantum schemes, or with classical
ECDSA on secp256k1 or secp256r1. Nonetheless, peer identities (Ethereum Node Records) can be signed solely with standard ECDSA or SECP256K1-MLDSA44. Standard
Ethereum transactions keep working unchanged.

This documentation covers only what differs from upstream Besu. For everything else, see the
[Besu user documentation](https://besu.hyperledger.org).

> ## ⚡ Skip the theory
>
> Build the node, start a four-validator network and send a post-quantum transaction:
> **[Quick start →](00-quick-start.md)**

## What changed compared with upstream Besu

| Area | Change | Details |
|---|---|---|
| Cryptography | A pluggable DSA layer. It supports SECP256K1, SECP256R1, ML-DSA-44/65/87 and Falcon-512, plus the hybrids SECP256K1-MLDSA44 and SECP256K1-FALCON512 | [Cryptography](03-cryptography/README.md) |
| Transactions | Four new *flexible* transaction types, `0x41`–`0x44`. Each carries its DSA type, its signature and the signer's public key, and the types also cover flexible code delegations | [Transactions](04-transactions.md) |
| Consensus | QBFT, IBFT 2.0 and Clique accept validators whose keys cannot be recovered from a signature. Messages and seals carry the signer's public key | [Consensus](05-consensus.md) |
| Networking | Node IDs, discovery (discv4) packets and node records (ENR) are signed with the node's DSA | [Networking](06-networking.md) |
| JSON-RPC | The new `VNT` namespace with `vnt_getAccountsSupportedDSAs`; transaction objects gain `dsaType` and `publicKey` | [JSON-RPC API](07-json-rpc-api.md) |
| Configuration | New options flags `--node-dsa` and `--accounts-supported-dsas` | [Configuration](10-configuration.md) |
| Tooling | Signature metrics and a microbenchmark that expresses verification cost in gas | [Metrics and performance](12-metrics-and-performance.md) |

## Table of contents

0. [⚡ Quick start](00-quick-start.md): build, start a network, send one transaction
1. [Motivation and design](01-motivation-and-design.md): the quantum threat, design goals, the hybrid approach
2. [Architecture](02-architecture.md): module map and life-cycle diagrams
3. [Cryptography](03-cryptography/README.md): the DSA abstraction layer
   1. [Algorithms](03-cryptography/algorithms.md): the algorithm registry, sizes and identifiers
   2. [Hybrid signatures](03-cryptography/hybrid-signatures.md): composite keys and signatures
   3. [Key management](03-cryptography/key-management.md): node keys, encodings, key agreement
4. [Transactions](04-transactions.md): flexible transaction types and their validation
5. [Consensus](05-consensus.md): QBFT, IBFT 2.0 and Clique with any DSA
6. [Networking](06-networking.md): node identity, discovery and node records
7. [JSON-RPC API](07-json-rpc-api.md): new methods and fields
8. [Security considerations](08-security.md): threat model, guarantees and limitations
9. [Installation](09-installation.md): building from source and Docker images
10. [Configuration](10-configuration.md): options, genesis and compatibility matrix
11. [Usage](11-usage/README.md): the companion projects
    1. [Running a network](11-usage/running-a-network.md)
    2. [Sending transactions](11-usage/sending-transactions.md)
12. [Metrics and performance](12-metrics-and-performance.md): metrics and the DSA microbenchmark
13. [Testing and compatibility](13-testing.md): test suites and upstream compatibility

Each page has a navigation bar at the top and the bottom. Follow **Next →** to read the documentation in order.

## Companion projects

| Project | Purpose |
|---|---|
| [besu-qbft](https://github.com/venturusbr/besu-qbft) | Scripts that generate and start a local QBFT network of N validators |
| [besu-flex-wallet-ppi](https://github.com/venturusbr/besu-flex-wallet-ppi) | A command-line wallet that signs and sends flexible (hybrid post-quantum) and standard EIP-1559 transactions |

## Glossary

| Term | Meaning |
|---|---|
| **DSA** | Digital signature algorithm. In this fork, a named *parameter set* such as `MLDSA44` or `SECP256K1-MLDSA44`, identified by a 2-byte ID |
| **PQC** | Post-quantum cryptography: algorithms believed to resist attacks by cryptographically relevant quantum computers |
| **ML-DSA** | Module-Lattice-Based Digital Signature Algorithm, standardized in NIST FIPS 204 (formerly CRYSTALS-Dilithium) |
| **Falcon** | A lattice-based signature scheme selected by NIST, with compact signatures (FN-DSA, draft FIPS 206) |
| **Hybrid signature** | A signature made of a classical ECDSA signature and a post-quantum signature. It is valid only if both parts verify |
| **PKR** | Public-key recovery: computing the signer's public key from a signature and the message, as ECDSA allows. Post-quantum schemes do not support it (only Falcon supports it in a second mode, which is not applicable in this work)|
| **Recoverable / non-recoverable DSA** | Whether a DSA supports PKR. Data signed with a non-recoverable DSA must also carry the signer's public key |
| **Flexible transaction** | A transaction of type `0x41`–`0x44` and signature agnostic that names its DSA and carries the signer's public key |
| **Node DSA** | The DSA of a node's own key, used for consensus, block seals and P2P identity (`--node-dsa`) |
| **Account DSA** | A DSA that externally owned accounts may use to sign transactions (`--accounts-supported-dsas`) |

## About this project

This experimental fork is developed by [Venturus](https://www.venturus.org.br).

---

**🏠 Index** · [⚡ Quick start](00-quick-start.md) · [Next: Quick start →](00-quick-start.md)
