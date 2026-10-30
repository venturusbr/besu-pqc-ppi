# Besu PQC: a post-quantum fork of Hyperledger Besu

> **This repository is a fork of [Hyperledger Besu](https://github.com/hyperledger/besu) 26.1.0.**

**besu-pqc-ppi** makes Besu agnostic to the digital signature algorithm. Transactions, EIP-7702 code delegations,
consensus messages (QBFT, IBFT 2.0, Clique) and block seals and discovery v4 packets can be signed with the post-quantum
algorithms **ML-DSA** (FIPS 204) and **Falcon-512**, with **hybrid** ECDSA + post-quantum schemes, or with classical
ECDSA on secp256k1 or secp256r1. Nonetheless, peer identities (Ethereum Node Records) can be signed solely with standard ECDSA or SECP256K1-MLDSA44. Standard Ethereum transactions keep working unchanged. The goal is to prepare
permissioned Ethereum networks for the arrival of quantum computers that can break ECDSA.

- ⚡ **[Quick start](docs/pqc/00-quick-start.md)**: build, start a four-validator network and send a post-quantum transaction
- 📖 **[Fork documentation](docs/pqc/README.md)**: architecture, cryptography, transactions, consensus, networking, APIs, security, configuration and usage
- 🧰 Companion projects: [besu-qbft](https://github.com/venturusbr/besu-qbft) (network scripts) and
  [besu-flex-wallet-ppi](https://github.com/venturusbr/besu-flex-wallet-ppi) (post-quantum wallet)

# Acknowledgement 
> This work was supported by the Ministério da Ciência, Tecnologia e Inovação (MCTI) under Law
No. 8,248 of October 23, 1991, through the PPI-SOFTEX program, coordinated by Softex, and published under PDI 19,
DOU 01245.010909/2024-41.

---
The rest of this file is the original Besu README.

# Besu Ethereum Client
 [![CircleCI](https://circleci.com/gh/hyperledger/besu/tree/main.svg?style=svg)](https://circleci.com/gh/hyperledger/besu/tree/main)
 [![CodeQL](https://github.com/hyperledger/besu/actions/workflows/codeql.yml/badge.svg)](https://github.com/hyperledger/besu/actions/workflows/codeql.yml)
 [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3174/badge)](https://bestpractices.coreinfrastructure.org/projects/3174)
 [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/hyperledger/besu/blob/main/LICENSE)
 [![Discord](https://img.shields.io/discord/905194001349627914?logo=Hyperledger&style=plastic)](https://discord.com/invite/hyperledger)
 [![Twitter Follow](https://img.shields.io/twitter/follow/HyperledgerBesu)](https://twitter.com/HyperledgerBesu)

[Download](https://github.com/hyperledger/besu/releases)

Besu is an Apache 2.0 licensed, MainNet compatible, Ethereum client written in Java.

## Useful Links

* [Besu User Documentation]
* [Besu Issues]
* [Besu Wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/)
* [How to Contribute to Besu](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22156850/How+to+Contribute)
* [Besu Roadmap & Planning](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154278/Besu+Roadmap+Planning)


## Issues 

Besu issues are tracked [in the github issues tab][Besu Issues].
See our [guidelines](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154243/Issues) for more details on searching and creating issues.

If you have any questions, queries or comments, [Besu channel on Discord] is the place to find us.


## Besu Users

To install the Besu binary, follow [these instructions](https://besu.hyperledger.org/public-networks/get-started/install/binary-distribution).    

## Besu Developers

* [Contributing Guidelines]
* [Coding Conventions](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154259/Coding+Conventions)
* [Command Line Interface (CLI) Style Guide](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154260/Besu+CLI+Style+Guide)
* [Besu User Documentation] for running and using Besu


### Development

Instructions for how to get started with developing on the Besu codebase. Please also read the
[wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154251/Pull+Requests) for more details on how to submit a pull request (PR).  

* [Checking Out and Building](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154264/Building+from+source)
* [Code Coverage](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154288/Code+coverage)
* [Logging](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154291/Logging) or the [Documentation's Logging section](https://besu.hyperledger.org/public-networks/how-to/monitor/logging)

### Profiling Besu

Besu supports performance profiling using [Async Profiler](https://github.com/async-profiler/async-profiler), a low-overhead sampling profiler.  
You can find setup and usage instructions in the [Profiling Guide](docs/PROFILING.md).

Profiling can help identify performance bottlenecks in block processing, transaction validation, and EVM execution.  
Please ensure the profiler is run as the same user that started the Besu process.

## Release Notes

[Release Notes](CHANGELOG.md)

## Reference Tests and JSON Tracing

Besu includes support for running Ethereum reference tests and generating detailed EVM execution traces.

To learn how to run the tests and enable opcode-level JSON tracing for debugging and correctness verification, see the [Reference Test Execution and Tracing Guide](REFERENCE_TESTS.md).

[Besu Issues]: https://github.com/hyperledger/besu/issues
[Besu User Documentation]: https://besu.hyperledger.org
[Besu channel on Discord]: https://discord.com/invite/hyperledger
[Contributing Guidelines]: CONTRIBUTING.md
