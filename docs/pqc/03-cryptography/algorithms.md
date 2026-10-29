[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Cryptography](README.md) · [← Previous: Cryptography](README.md) · [Next: Hybrid signatures →](hybrid-signatures.md)

---

# Algorithms

## Contents

- [Identifiers and sizes](#identifiers-and-sizes)
- [ECDSA: SECP256K1 and SECP256R1](#ecdsa-secp256k1-and-secp256r1)
- [ML-DSA](#ml-dsa)
- [Falcon-512](#falcon-512)
- [Hybrids](#hybrids)
- [Where each algorithm can be used](#where-each-algorithm-can-be-used)
- [Adding an algorithm](#adding-an-algorithm)

## Identifiers and sizes

Every DSA is a constant of `DSAParametersSet`
(`crypto/algorithms/.../algorithms/parameters/DSAParametersSet.java`). The 2-byte identifier is what goes on the wire
(the `dsaType` field), and the name is what the CLI options use.

| Name | ID | Private key (B) | Public key (B) | Signature (B) | Recoverable | Standard |
|---|---|---|---|---|---|---|
| `SECP256K1` | `0x0001` | 32 | 64 | 65 | ✓ | SEC 2 (Ethereum default) |
| `SECP256R1` | `0x0002` | 32 | 64 | 65 | ✓ | NIST P-256 |
| `MLDSA44` | `0x0030` | 2560 | 1312 | 2420 | — | FIPS 204, category 2 |
| `MLDSA65` | `0x0031` | 4032 | 1952 | 3309 | — | FIPS 204, category 3 |
| `MLDSA87` | `0x0032` | 4896 | 2592 | 4627 | — | FIPS 204, category 5 |
| `FALCON512` | `0x0040` | 2176 | 896 | variable, ≤ 752 | — | Falcon round 3 (FN-DSA), category 1 |
| `SECP256K1-MLDSA44` | `0x0060` | 2592 | 1376 | 2485 | ECDSA half only | hybrid |
| `SECP256K1-FALCON512` | `0x0070` | 2208 | 960 | 65 + variable | ECDSA half only | hybrid |

Identifier ranges: `0x00 0x0X` classical, `0x003X` ML-DSA, `0x004X` Falcon, `0x006X` secp256k1 + ML-DSA hybrids,
`0x007X` hybrids with other post-quantum algorithms.

> In the source, the constructor arguments are `(id, name, privateKeyLength, publicKeyLength, signatureLength,
> seedLength)`. The private key length comes **before** the public key length.

All post-quantum code uses **Bouncy Castle** (`bcprov-jdk18on` 1.80.x) through its low-level `org.bouncycastle.pqc.crypto`
API. ECDSA uses Besu's native secp256k1 and secp256r1 libraries when they are available.

## ECDSA: SECP256K1 and SECP256R1

These are upstream's algorithms. They now also implement `DigitalSignatureAlgorithm` and `PublicKeyRecoverable`.

- **`SECP256K1`** signs deterministically (RFC 6979). **`SECP256R1`** uses a random nonce.
- Both sign a 32-byte message, normally a Keccak-256 hash.
- A signature remembers its curve. The low-`s` malleability check uses the half order of that curve.
- `SECP256R1` support (also as an account DSA) was added together with the rule that `--node-dsa` must sign on the
  genesis `ecCurve` (see [Configuration](../10-configuration.md#genesis-eccurve-and-node-dsa)).

## ML-DSA

Implemented by `crypto/algorithms/.../algorithms/MLDSA.java`. Three parameter sets are available: `MLDSA44`,
`MLDSA65` and `MLDSA87`.

| Aspect | Behaviour |
|---|---|
| Variant | Pure ML-DSA with an empty context string, applied to the message passed in (a 32-byte hash for transactions and consensus). Not HashML-DSA |
| Randomness | **Deterministic** signing (FIPS 204 deterministic variant: no random input is given to the signer) |
| Thread safety | A new Bouncy Castle `MLDSASigner` is created for each signature and each verification, because the signer keeps SHAKE state |
| Private key | Stored in the **expanded** form (`rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0`). A 32-byte input is treated as a **seed** and expanded when loaded |
| Public key | Always derived from the private key when a key is loaded |
| Key generation | Bouncy Castle `MLDSAKeyPairGenerator` with Besu's `SecureRandom` |

## Falcon-512

Implemented by `crypto/algorithms/.../algorithms/Falcon.java`, parameterized by `DSAParametersSet`. Only
`FALCON512` is registered.

| Aspect | Behaviour |
|---|---|
| Encoding | Falcon round-3 encoding, as produced by Bouncy Castle |
| Randomness | **Randomized**: each signature uses a fresh nonce from `SecureRandom` |
| Signature length | Variable, typically 650–660 bytes. Accepted up to **752** bytes, the liboqs maximum for Falcon-512, and never padded |
| Private key | `f ‖ g ‖ F ‖ h` (384 + 384 + 512 + 896 = 2176 bytes). The public key `h` is appended on purpose, because Bouncy Castle cannot derive it from `f, g, F` |
| Public key | `h` (896 bytes), without the 1-byte header used by FIPS-style encodings |
| Verification | Returns `false`, rather than throwing, for a wrong key length, an empty signature or a malformed encoding |
| Secrets | Private keys compare in constant time and are redacted in `toString()` |

> **Falcon status.** Falcon-512 is fully supported for **account** signatures (transactions and code delegations). As a
> **node** DSA (`SECP256K1-FALCON512`), it works for consensus but has peer-discovery limitations. See
> [Networking](../06-networking.md#falcon-node-keys).

## Hybrids

`SECP256K1-MLDSA44` and `SECP256K1-FALCON512` combine ECDSA on secp256k1 with a post-quantum algorithm. Both are built by
`HybridStrongNestingConcatenation` and described in [Hybrid signatures](hybrid-signatures.md). Hybrids are available only
on networks whose genesis `ecCurve` is secp256k1 (the default).

## Where each algorithm can be used

| DSA | Account DSA (transactions) | Node DSA (consensus, P2P) |
|---|---|---|
| `SECP256K1` | ✓ (also standard transactions) | ✓ default |
| `SECP256R1` | ✓ | ✓ on `ecCurve: secp256r1` networks |
| `MLDSA44/65/87` | ✓ | — (see note) |
| `FALCON512` | ✓ | — (see note) |
| `SECP256K1-MLDSA44` | ✓ | ✓ |
| `SECP256K1-FALCON512` | ✓ | ⚠ experimental (static peers only) |

Note: a node whose key is purely post-quantum cannot complete the RLPx handshake, which needs an elliptic-curve key for
ECDH. Use a hybrid as the node DSA. See [Key management](key-management.md#key-agreement-ecdh).

## Adding an algorithm

1. Implement `DigitalSignatureAlgorithm` (and `PublicKeyRecoverable` if the algorithm supports recovery), plus its
   `Signature` and key types.
2. Add a constant to `DSAParametersSet` with a free identifier and the key and signature sizes.
3. Register a factory in `SupportedAlgorithms`.
4. Teach `KeyFactory` (key decoding and derivation) and `SignatureFactory` (signature decoding) about the new
   parameter set.
5. Add the parameter set to the parameterized tests, for example `SignAndBuildTest` and the BFT integration tests.

---

[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Cryptography](README.md) · [← Previous: Cryptography](README.md) · [Next: Hybrid signatures →](hybrid-signatures.md)
