cpuminer-multi
==============

[![build](https://github.com/Justinwold88/cpuminer-multi/actions/workflows/build.yml/badge.svg)](https://github.com/Justinwold88/cpuminer-multi/actions/workflows/build.yml)

A multi-threaded CPU miner for many proof-of-work algorithms, for Linux,
macOS and Windows on x86-64, 32-bit x86, ARM64 and 32-bit ARM.

This is a maintained fork of [Lucas Jones's cpuminer-multi](https://github.com/lucasjones/cpuminer-multi),
itself a fork of [pooler's cpuminer](https://github.com/pooler/cpuminer)
(see [AUTHORS](AUTHORS)). It fixes the bugs that stopped several algorithms and
all solo mining from working, replaces what had died since 2015 (getwork,
Travis CI, the Dockerfile), and is tested on every platform on every change.
See [NEWS](NEWS) for what changed.

#### Contents

* [Algorithms](#algorithms)
* [Download](#download)
* [Building](#building)
* [Usage](#usage)
* [Credits](#credits)
* [License](#license)

Algorithms
==========

| `-a` | Coins | Status |
|------|-------|--------|
| `sha256d` | Bitcoin, Bitcoin Cash, Peercoin, ... | works |
| `scrypt` | Litecoin, Dogecoin | works |
| `x11` | Dash | works |
| `blake` | Blakecoin, and the coins merge-mined with it (Photon, Electron, Universal Molecule, Lithium, BlakeBitcoin) | works (fixed in this fork) |
| `skein` | DigiByte (Skein) | works (fixed in this fork) |
| `qubit` | DigiByte (Qubit) | works (new in this fork) |
| `cryptonight` | Bytecoin and other coins on the original CryptoNight | works (fixed in this fork) |
| `scrypt:N` | scrypt with N other than 1024 (Vertcoin used it until 2014) | legacy |
| `keccak` | Maxcoin | legacy |
| `quark` | Quarkcoin | legacy |
| `x13`, `x14`, `x15` | Sherlockcoin, X14coin, RadianceCoin, ... | legacy |
| `fresh` | FreshCoin | legacy |
| `shavite3` | INKcoin | legacy |

**Works**: tested end to end, from the pool's messages to the shares or
blocks it accepts. **Legacy**: the hashing is tested, but we know of no
active network that still uses the algorithm; it is kept for completeness.

Bitcoin, Litecoin, Dogecoin, Dash and DigiByte are mined with ASICs or GPUs
today, so a CPU earns next to nothing on them. They are useful for testing
and for testnets.

Monero left CryptoNight for **RandomX** in 2019, and Vertcoin, Feathercoin
and Myriad moved to other algorithms too. Planned: RandomX, DigiByte's
Odocrypt, NeoScrypt, Verthash, Argon2d and Yescrypt.

Removed: Heavycoin's `heavy` (its network is gone, and the implementation was
broken) and the unused scrypt-jane sources.

Download
========

* Source: `git clone https://github.com/Justinwold88/cpuminer-multi`
* Windows: every build on GitHub Actions keeps `minerd.exe` with the DLLs it
  needs, under *Actions → build → the latest run → Artifacts*.

Building
========

You need a C compiler, GNU make, autoconf, automake, pkg-config,
[libcurl](https://curl.se/libcurl/) and [jansson](https://github.com/akheron/jansson) 2.7 or newer.

Then, in the source directory:

    ./autogen.sh
    ./configure CFLAGS="-O2 -march=native"
    make
    make check

`-march=native` makes the fastest code for the machine you build on, but the
binary may not run on other CPUs; leave it out for a portable binary.
`make check` runs the known-answer tests: every algorithm must reproduce
reference hashes and find a planted share. `make install` installs `minerd`
and its man page.

#### Linux

Install the tools and libraries first:

* Debian, Ubuntu: `sudo apt install build-essential autoconf automake pkg-config libcurl4-openssl-dev libjansson-dev`
* Fedora: `sudo dnf install gcc make autoconf automake pkgconf-pkg-config libcurl-devel jansson-devel`
* Arch: `sudo pacman -S --needed base-devel curl jansson`

#### macOS

With [Homebrew](https://brew.sh): `brew install autoconf automake pkgconf jansson`.
macOS comes with libcurl. This works on Apple Silicon and on Intel Macs.

#### Windows

Use [MSYS2](https://www.msys2.org). In its **UCRT64** shell:

    pacman -S --needed autoconf automake make mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-curl mingw-w64-ucrt-x86_64-jansson mingw-w64-ucrt-x86_64-pkgconf

Then build as above. To run `minerd.exe` outside the MSYS2 shell, copy the DLLs
it needs next to it:

    ldd minerd.exe | awk '$3 ~ /\/ucrt64\// { print $3 }' | xargs cp -t .

#### Docker

    docker build -t cpuminer-multi .
    docker run --rm cpuminer-multi -a sha256d -o stratum+tcp://POOL:PORT -u USER -p PASS

The image is built for the platform it is built on (amd64 or arm64). For the
fastest code on one machine, build there with
`--build-arg CFLAGS="-O2 -march=native"`.

#### Notes by architecture

* **x86-64**: uses SSE2, AVX, AVX2 and XOP assembly for scrypt and SHA-256d
  when both the CPU and the operating system support them (Linux 2.6.30,
  FreeBSD 9.1, OS X 10.6.8, Windows 7 SP1 and later). configure warns if the
  assembler lacks an instruction set; the miner still builds without it.
* **32-bit x86**: SSE2 assembly for scrypt and SHA-256d, picked at run time.
* **x86, 32 and 64-bit**: CryptoNight uses AES-NI when the CPU has it. On
  Linux, its 2 MiB scratchpad goes on a transparent huge page when the
  kernel allows it (`/sys/kernel/mm/transparent_hugepage/enabled` set to
  `madvise` or `always`, the default on most distributions).
* **ARM64** (Raspberry Pi 3 and later with a 64-bit OS, Apple Silicon, AWS
  Graviton): portable C code.
* **32-bit ARM**: assembly for ARMv5E and later, chosen when compiling. Add
  `-mfpu=neon` to `CFLAGS` to use NEON.
* `./configure --disable-assembly` builds everything from portable C.
* AIX: export `OBJECT_MODE=64` for a 64-bit build. Long options are only
  available through a configuration file.

Usage
=====

Run `minerd --help` for all the options, or see `man minerd`.

#### Pool mining (stratum)

    minerd -a scrypt -o stratum+tcp://pool.example.com:3333 -u USER.WORKER -p x

`-t N` sets the number of threads (default: one per processor). If the pool
expresses difficulty for a different "difficulty 1" than the miner expects,
`-f N` divides the pool's difficulty by N.

#### Solo mining (getblocktemplate)

Mine against your own node for any Bitcoin-style coin that uses one of the
algorithms above. Enable its RPC server (`server=1`, `rpcuser`, `rpcpassword`
in its configuration file), let it sync, then:

    minerd -a sha256d -o http://127.0.0.1:8332 -u RPCUSER -p RPCPASS --coinbase-addr=YOUR_ADDRESS

The reward goes to `--coinbase-addr`. The miner asks the node what output
script that address pays to (so any address type the node knows works:
legacy, P2SH, segwit, taproot), and refuses to start if the node says the
address belongs to another coin or network. `--coinbase-sig=TEXT` adds text to
your blocks. Long polling, segwit (BIP 141) and the BIP 34 height rule are
supported. A coin whose node requires a rule this miner does not implement
(Litecoin's MWEB, for example) is refused with a message: mine it through a
pool. Dash-style masternode payments are not supported either.

DigiByte's node makes block templates for one of its algorithms at a time
(its `algo=` setting, scrypt by default); the miner asks it for the one it
mines (`sha256d`, `scrypt`, `skein` or `qubit`), so the node needs no
particular setting.

Servers that only speak getwork, the protocol getblocktemplate replaced, are
still supported; `--no-gbt` and `--no-getwork` choose between the two.

#### CryptoNight

    minerd -a cryptonight -o stratum+tcp://pool.example.com:3333 -u WALLET_ADDRESS -p x

#### Benchmark

    minerd -a x11 --benchmark

#### Configuration file

`-c FILE` reads options from a JSON file that maps long option names to their
values; see [example-cfg.json](example-cfg.json).

#### Connecting through a proxy

Use the `--proxy` option. For a SOCKS proxy, add a `socks4://` or `socks5://`
prefix to the proxy host; `socks4a://` and `socks5h://` resolve host names
through the proxy. Without a prefix, the proxy is taken to be an HTTP proxy.
Without `--proxy`, the `http_proxy` and `all_proxy` environment variables are
honoured.

Credits
=======

cpuminer-multi was forked from pooler's cpuminer and developed by Lucas Jones.

* [tpruvot](https://github.com/tpruvot) added features and the SHA-3 based algorithms
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight
* getblocktemplate support is based on pooler's cpuminer 2.5

Lucas Jones accepted donations for his work on cpuminer-multi at:

* XMR: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

License
=======

GPLv2 or later. See [COPYING](COPYING) for details.
