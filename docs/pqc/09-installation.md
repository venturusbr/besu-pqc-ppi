[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Security considerations](08-security.md) · [Next: Configuration →](10-configuration.md)

---

# Installation

> Looking for the shortest path? See the [⚡ Quick start](00-quick-start.md).

## Contents

- [Requirements](#requirements)
- [Getting the source](#getting-the-source)
- [Building the distribution](#building-the-distribution)
- [Building the Docker image](#building-the-docker-image)
- [Running the tests](#running-the-tests)
- [Verifying the installation](#verifying-the-installation)

## Requirements

| Requirement | Notes |
|---|---|
| JDK 21 or later | The build fails with older versions (`build.gradle` checks the Java version) |
| Git | Gradle also clones the [forked discovery library](06-networking.md#the-forked-discovery-library) during the build |
| Internet access | Maven dependencies, the discovery library from GitHub, and the Pyroscope agent used by the Docker image |
| Docker (optional) | For the Docker image and the [companion network scripts](11-usage/running-a-network.md) |
| Linux, macOS, or WSL 2 or Git Bash on Windows | On Windows, Gradle's Docker tasks call `bash` through WSL, even when Gradle runs from Git Bash |

## Getting the source

```bash
git clone https://github.com/venturusbr/besu-pqc-ppi.git
```

```bash
cd besu-pqc-ppi
```

## Building the distribution

```bash
./gradlew -Pversion=26.1.0-pqc installDist
```

The runnable distribution is created in `build/install/besu`:

```bash
build/install/besu/bin/besu --version
```

To create archives (`build/distributions/besu-26.1.0-pqc.tar.gz` and `.zip`):

```bash
./gradlew -Pversion=26.1.0-pqc distTar distZip
```

> `gradle.properties` still carries an old default version. Pass `-Pversion=26.1.0-pqc` so that artifacts and images get
> a meaningful version.

To build against a local checkout of the discovery library instead of cloning it:

```bash
./gradlew -PdiscoveryPath=/path/to/discovery-besu-ppi installDist
```

## Building the Docker image

```bash
./gradlew -Pversion=26.1.0-pqc -Prelease.releaseVersion=26.1.0-pqc distDocker
```

This produces the image `hyperledger/besu:26.1.0-pqc`, the tag that the
[besu-qbft](11-usage/running-a-network.md) scripts use by default. Override the name with `-PdockerOrgName=...` and
`-PdockerArtifactName=...`.

The image is based on `ubuntu:24.04` with a Temurin JRE, and its entry point is `besu-entry.sh`. Inside the container,
`/usr/app` is used by the companion scripts as the working directory, and the
[signature metrics](12-metrics-and-performance.md#signature-metrics-csv) are written there.

**Building the image without WSL (Windows)** — build the distribution, then run `docker build` by hand, for example
from Git Bash:

```bash
./gradlew -Pversion=26.1.0-pqc distTar
```

```bash
mkdir -p build/docker-besu && tar -xzf build/distributions/besu-26.1.0-pqc.tar.gz -C build/docker-besu && mv build/docker-besu/besu-26.1.0-pqc build/docker-besu/besu && cp docker/Dockerfile docker/pyroscope.properties build/docker-besu/
```

```bash
docker build --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" --build-arg VERSION=26.1.0-pqc --build-arg VCS_REF="$(git rev-parse --short HEAD)" -t hyperledger/besu:26.1.0-pqc build/docker-besu
```

## Running the tests

| Scope | Command |
|---|---|
| Crypto layer | `./gradlew :crypto:algorithms:test` |
| Transactions, encoders, validation | `./gradlew :ethereum:core:test` |
| JSON-RPC | `./gradlew :ethereum:api:test` |
| QBFT integration tests under every post-quantum DSA | `./gradlew :consensus:qbft-core:integrationTestPqc` |
| IBFT 2.0 integration tests under every post-quantum DSA | `./gradlew :consensus:ibft:integrationTestPqc` |
| Everything (long) | `./gradlew build` |

See [Testing and compatibility](13-testing.md) for details.

## Verifying the installation

Start a throwaway node that only serves the RPC API, and ask it which account DSAs it enables:

```bash
build/install/besu/bin/besu --network=dev --data-path=/tmp/besu-pqc --rpc-http-enabled --rpc-http-api=ETH,NET,WEB3,VNT --accounts-supported-dsas=SECP256K1,MLDSA44,SECP256K1-MLDSA44
```

The start-up log contains:

```text
Account-enabled DSAs: SECP256K1, MLDSA44, SECP256K1-MLDSA44
```

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"vnt_getAccountsSupportedDSAs","params":[],"id":1}' http://localhost:8545
```

```json
{"jsonrpc":"2.0","id":1,"result":["SECP256K1","MLDSA44","SECP256K1-MLDSA44"]}
```

To run a real network, continue with [Configuration](10-configuration.md) and
[Running a network](11-usage/running-a-network.md).

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Security considerations](08-security.md) · [Next: Configuration →](10-configuration.md)
