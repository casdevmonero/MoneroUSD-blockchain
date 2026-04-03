# MoneroUSD Blockchain v1.0.0

Copyright (c) 2024-2026 MoneroUSD.
Portions Copyright (c) 2018-2024 Haven Protocol.
Portions Copyright (c) 2014-2022 The Monero Project.
Portions Copyright (c) 2012-2013 The CryptoNote developers.

## Table of Contents

  - [Development resources](#development-resources)
  - [Introduction](#introduction)
  - [About this project](#about-this-project)
  - [Supporting the project](#supporting-the-project)
  - [License](#license)
  - [Contributing](#contributing)
  - [Compiling MoneroUSD from source](#compiling-monerousd-from-source)
    - [Dependencies](#dependencies)
  - [Internationalization](#Internationalization)
  - [Using Tor](#using-tor)
  - [Pruning](#Pruning)
  - [Debugging](#Debugging)
  - [Known issues](#known-issues)

## Development resources

- Web: [monerousd.org](https://monerousd.org)
- GitHub: [https://github.com/casdevmonero/MoneroUSD-blockchain](https://github.com/casdevmonero/MoneroUSD-blockchain)

## Introduction

MoneroUSD (USDm) is a private, secure, untraceable decentralised stablecoin built on Monero's FCMP++ privacy technology. You are your bank, you control your funds, and nobody can trace your transfers unless you allow them to do so.

**Privacy:** MoneroUSD uses FCMP++ (Full-Chain Membership Proofs) — Monero's next-generation privacy protocol — to ensure that every transaction is cryptographically private by default. Your purchases, receipts, and transfers remain completely confidential.

**Stability:** USDm is pegged 1:1 to USD through an on-chain protocol mechanism. The system includes an adaptive reserve failsafe engine with five-phase crisis response to maintain the peg under extreme market conditions.

**Security:** Every transaction on the network is cryptographically secured through a distributed peer-to-peer consensus network. Individual wallets have a 25-word mnemonic seed displayed once at creation that can be written down to back up the wallet. Wallet files should be encrypted with a strong passphrase.

**Untraceability:** Ring signatures and FCMP++ ensure that transactions are not only untraceable but have an optional measure of ambiguity that ensures transactions cannot be tied back to an individual user or computer.

**Decentralization:** The utility of MoneroUSD depends on its decentralised peer-to-peer consensus network. Anyone can run the MoneroUSD software, validate the integrity of the blockchain, and participate in all aspects of the network using consumer-grade hardware.

**P2P Privacy:** Dandelion++ routing is used at the network layer to obscure the origin IP address of transactions before they propagate across the network.

**Adaptive Protocol:** Block size and fees adapt dynamically to network conditions. The protocol enforces core consensus rules that prevent abuse while keeping the network efficient.

## About this project

This is the core implementation of MoneroUSD. It is open source and completely free to use without restrictions, except for those specified in the license agreement below. There are no restrictions on anyone creating an alternative implementation of MoneroUSD that uses the protocol and network in a compatible manner.

The repository on GitHub is the staging area for the latest changes. Before changes are merged into the master branch, they are tested by individual developers in their own branches, submitted as a pull request, and reviewed. The repository should be carefully considered before use in a production environment — it is generally better to use a tagged release for stability.

**Anyone is welcome to contribute to MoneroUSD's codebase!** If you have a fix or code change, feel free to submit it as a pull request directly to the `master` branch.

## Supporting the project

MoneroUSD is a community-driven project. The best way to support it is to run a node, contribute code, or spread the word.

## License

See [LICENSE](LICENSE).

## Contributing

If you want to help out, see [CONTRIBUTING](docs/CONTRIBUTING.md) for a set of guidelines.

## Compiling MoneroUSD from source

### Dependencies

The following table summarizes the tools and libraries required to build. A
few of the libraries are also included in this repository (marked as
"Vendored"). By default, the build uses the library installed on the system
and ignores the vendored sources. However, if no library is found installed on
the system, then the vendored source will be built and used. The vendored
sources are also used for statically-linked builds because distribution
packages often include only shared library binaries (`.so`) but not static
library archives (`.a`).

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg    | Arch pkg     | Void pkg           | Fedora pkg          | Optional | Purpose         |
| ------------ | ------------- | -------- | -------------------- | ------------ | ------------------ | ------------------- | -------- | --------------- |
| GCC          | 5             | NO       | `build-essential`    | `base-devel` | `base-devel`       | `gcc`               | NO       |                 |
| CMake        | 3.5           | NO       | `cmake`              | `cmake`      | `cmake`            | `cmake`             | NO       |                 |
| pkg-config   | any           | NO       | `pkg-config`         | `base-devel` | `base-devel`       | `pkgconf`           | NO       |                 |
| Boost        | 1.58          | NO       | `libboost-all-dev`   | `boost`      | `boost-devel`      | `boost-devel`       | NO       | C++ libraries   |
| OpenSSL      | basically any | NO       | `libssl-dev`         | `openssl`    | `libressl-devel`   | `openssl-devel`     | NO       | sha256 sum      |
| libzmq       | 4.2.0         | NO       | `libzmq3-dev`        | `zeromq`     | `zeromq-devel`     | `zeromq-devel`      | NO       | ZeroMQ library  |
| OpenPGM      | ?             | NO       | `libpgm-dev`         | `libpgm`     |                    | `openpgm-devel`     | NO       | For ZeroMQ      |
| libnorm[2]   | ?             | NO       | `libnorm-dev`        |              |                    |                     | YES      | For ZeroMQ      |
| libunbound   | 1.4.16        | YES      | `libunbound-dev`     | `unbound`    | `unbound-devel`    | `unbound-devel`     | NO       | DNS resolver    |
| libsodium    | ?             | NO       | `libsodium-dev`      | `libsodium`  | `libsodium-devel`  | `libsodium-devel`   | NO       | cryptography    |
| libunwind    | any           | NO       | `libunwind8-dev`     | `libunwind`  | `libunwind-devel`  | `libunwind-devel`   | YES      | Stack traces    |
| liblzma      | any           | NO       | `liblzma-dev`        | `xz`         | `liblzma-devel`    | `xz-devel`          | YES      | For libunwind   |
| libreadline  | 6.3.0         | NO       | `libreadline6-dev`   | `readline`   | `readline-devel`   | `readline-devel`    | YES      | Input editing   |
| expat        | 1.1           | NO       | `libexpat1-dev`      | `expat`      | `expat-devel`      | `expat-devel`       | YES      | XML parsing     |
| GTest        | 1.5           | YES      | `libgtest-dev`[1]    | `gtest`      | `gtest-devel`      | `gtest-devel`       | YES      | Test suite      |
| ccache       | any           | NO       | `ccache`             | `ccache`     | `ccache`           | `ccache`            | YES      | Compil. cache   |
| Doxygen      | any           | NO       | `doxygen`            | `doxygen`    | `doxygen`          | `doxygen`           | YES      | Documentation   |
| Graphviz     | any           | NO       | `graphviz`           | `graphviz`   | `graphviz`         | `graphviz`          | YES      | Documentation   |
| lrelease     | ?             | NO       | `qttools5-dev-tools` | `qt5-tools`  | `qt5-tools`        | `qt5-linguist`      | YES      | Translations    |
| libhidapi    | ?             | NO       | `libhidapi-dev`      | `hidapi`     | `hidapi-devel`     | `hidapi-devel`      | YES      | Hardware wallet |
| libusb       | ?             | NO       | `libusb-1.0-0-dev`   | `libusb`     | `libusb-devel`     | `libusbx-devel`     | YES      | Hardware wallet |
| libprotobuf  | ?             | NO       | `libprotobuf-dev`    | `protobuf`   | `protobuf-devel`   | `protobuf-devel`    | YES      | Hardware wallet |
| protoc       | ?             | NO       | `protobuf-compiler`  | `protobuf`   | `protobuf`         | `protobuf-compiler` | YES      | Hardware wallet |
| libudev      | ?             | NO       | `libudev-dev`        | `systemd`    | `eudev-libudev-devel` | `systemd-devel`  | YES      | Hardware wallet |

[1] On Debian/Ubuntu `libgtest-dev` only includes sources and headers. You must
build the library binary manually. This can be done with the following command `sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make`
then:

* on Debian:
  `sudo mv libg* /usr/lib/`
* on Ubuntu:
  `sudo mv lib/libg* /usr/lib/`

[2] libnorm-dev is needed if your zmq library was built with libnorm, and not needed otherwise

Install all dependencies at once on Debian/Ubuntu:

```
sudo apt update && sudo apt install build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz
```

Install all dependencies at once on Arch:
```
sudo pacman -Syu --needed base-devel cmake boost openssl zeromq libpgm unbound libsodium libunwind xz readline expat gtest python3 ccache doxygen graphviz qt5-tools hidapi libusb protobuf systemd
```

Install all dependencies at once on Fedora:
```
sudo dnf install gcc gcc-c++ cmake pkgconf boost-devel openssl-devel zeromq-devel openpgm-devel unbound-devel libsodium-devel libunwind-devel xz-devel readline-devel expat-devel gtest-devel ccache doxygen graphviz qt5-linguist hidapi-devel libusbx-devel protobuf-devel protobuf-compiler systemd-devel
```

### Cloning the repository

Clone recursively to pull in needed submodules:

```
git clone --recursive https://github.com/casdevmonero/MoneroUSD-blockchain
```

If you already have a repo cloned, initialize and update:

```
cd MoneroUSD-blockchain && git submodule init && git submodule update
```

*Note*: If there are submodule differences between branches, you may need
to use `git submodule sync && git submodule update` after changing branches
to build successfully.

### Build instructions

MoneroUSD uses the CMake build system and a top-level [Makefile](Makefile) that
invokes cmake commands as needed.

#### On Linux and macOS

* Install the dependencies
* Change to the root of the source code directory and build:

    ```bash
    cd MoneroUSD-blockchain
    git checkout master
    make
    ```

    *Optional*: If your machine has several cores and enough memory, enable
    parallel build by running `make -j<number of threads>` instead of `make`. For
    this to be worthwhile, the machine should have one core and about 2GB of RAM
    available per thread.

* The resulting executables can be found in `build/release/bin`

* Add `PATH="$PATH:$HOME/MoneroUSD-blockchain/build/release/bin"` to `.profile`

* Run the MoneroUSD daemon with `monerousd --detach`

* **Optional**: build and run the test suite to verify the binaries:

    ```bash
    make release-test
    ```

    *NOTE*: `core_tests` may take a few hours to complete.

* **Optional**: to build binaries suitable for debugging:

    ```bash
    make debug
    ```

* **Optional**: to build statically-linked binaries:

    ```bash
    make release-static
    ```

Dependencies need to be built with -fPIC. Static libraries usually aren't, so you may have to build them yourself with -fPIC. Refer to their documentation for how to build them.

* **Optional**: build documentation in `doc/html` (omit `HAVE_DOT=YES` if `graphviz` is not installed):

    ```bash
    HAVE_DOT=YES doxygen Doxyfile
    ```

#### On the Raspberry Pi

Tested on a Raspberry Pi Zero with a clean install of minimal Raspbian Stretch (2017-09-07 or later).

* `apt-get update && apt-get upgrade` to install all of the latest software

* Install the dependencies for MoneroUSD from the 'Debian' column in the table above.

* Increase the system swap size:

    ```bash
    sudo /etc/init.d/dphys-swapfile stop
    sudo nano /etc/dphys-swapfile
    CONF_SWAPSIZE=2048
    sudo /etc/init.d/dphys-swapfile start
    ```

* Clone MoneroUSD and build:

    ```bash
    git clone --recursive https://github.com/casdevmonero/MoneroUSD-blockchain
    cd MoneroUSD-blockchain
    make release
    ```

#### On Windows

* Download the [MSYS2 installer](https://www.msys2.org/), 64-bit version, and run it.

* Install the required packages:

    ```bash
    pacman -Syu
    pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-protobuf-c mingw-w64-x86_64-libusb git
    ```

* Open the MSYS2 MinGW 64-bit shell and clone the repository:

    ```bash
    git clone --recursive https://github.com/casdevmonero/MoneroUSD-blockchain
    cd MoneroUSD-blockchain
    make release-static-win64
    ```

* The resulting executables can be found in `build/release/bin`

### Running monerousd

The build places the binary in `bin/` sub-directory within the build directory
from which cmake was invoked. To run in the foreground:

```bash
./bin/monerousd
```

To list all available options, run `./bin/monerousd --help`. Options can be
specified either on the command line or in a configuration file passed by the
`--config-file` argument. To specify an option in the configuration file, add
a line with the syntax `argumentname=value`, where `argumentname` is the name
of the argument without the leading dashes, for example `log-level=1`.

To run in the background:

```bash
./bin/monerousd --log-file monerousd.log --detach
```

To run as a systemd service, copy
[monerousd.service](utils/systemd/monerousd.service) to `/etc/systemd/system/` and
[monerousd.conf](utils/conf/monerousd.conf) to `/etc/`. The [manual
page](docs/DAEMON.md) shows all the options available to monerousd service.

## Internationalization

See [README.i18n.md](docs/README.i18n.md).

## Using Tor

While MoneroUSD is not designed to integrate with Tor, it can be used wrapped with torsocks, if you add `--p2p-bind-ip 127.0.0.1` on the command line. You also want to set `DNS_PUBLIC=tcp` or `DNS_PUBLIC=stcp` if you have DNS related problems. See [ANONYMITY_NETWORKS](docs/ANONYMITY_NETWORKS.md) for more details.

## Pruning

As of March 2022 the blockchain file is about 130 GB. To minimize disk space, there are two options: pruning and a bootstrap node.

Pruning allows the running of a node with only 1/8 of the blockchain data. To use a pruned node, use `--prune-blockchain`. A pruned node uses about 45 GB of storage.

A bootstrap node just skips to the last synced block that a remote node is sharing. Bootstrap nodes are risky as they rely on the remote node providing correct data. To run a bootstrap node you use `--bootstrap-daemon-address address:port`.

## Debugging

See [COMPILING_DEBUGGING_TESTING.md](docs/COMPILING_DEBUGGING_TESTING.md) for debugging instructions.

## Known issues

See the GitHub [issues page](https://github.com/casdevmonero/MoneroUSD-blockchain/issues) for known issues and bug reports.
