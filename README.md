rlib
====

[![CI](https://github.com/haaspors/rlib/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/haaspors/rlib/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-LGPL-blue.svg)](https://github.com/haaspors/rlib/blob/master/LICENSE)

rlib is a c library which contains abstractions for OS, platform and CPU architecture.
It's a convenience library for useful things. :-)

API documentation is published at <https://haaspors.github.io/rlib/>.

**Note:**
*rlib is under active development.
Anything may change at any time.
The public API should NOT be considered stable.*

Platforms
--------
* Linux
* Darwin (OSX)
* Windows
* ...

Features
--------

### Foundations
* Strict primitive types, refcounting (`RRef`), atomic operations
* High-resolution clock and timing helpers
* CPU feature detection driving runtime SIMD dispatch

### Memory and buffers
* Refcounted memory chunks with pluggable allocators (`RMem`, `RMemAllocator`)
* Buffer abstraction, memory-mapped file regions, secure-clear helpers
* Inline byte-buffer primitives

### Data structures
* Hashtable, hashset, dictionary, ptr arrays, lists, queues, bitsets
* Mutable strings (`RString`)
* Multi-precision integer math (`rmpint`)
* Hazard-pointer reclamation, timeout callback lists

### Text and encoding
* ASCII classification and case helpers
* Unicode 16 — UTF-8 / UTF-16 / UTF-32 / WTF-8 with UCD-backed properties and simple case mapping
* Base64 (RFC 4648), JSON parser, CRC32 / CRC32C with HW dispatch

### Threads and tasks
* Threads, locks, atomics
* Threadpool with a task-queue front-end
* One-shot initialisation (`ROnce`)

### Event loop and I/O
* Edge-triggered event loop on `epoll` (Linux), `kqueue` (BSD / Darwin), IOCP (Windows)
* TCP, UDP, DNS-resolve and wakeup event sources
* Files, filesystem traversal, polling primitives

### Networking
* Sockets and socket addresses
* HTTP client and server, URI parser
* TLS client and server
* STUN, RTP / RTCP, SDP, SRTP
* WebRTC session, ICE transports, RTP listener / sender / receiver

### Cryptography
* AES (FIPS 197) with AES-NI, ARMv8-AES and PCLMULQDQ paths
* HMAC and message digests (MD5, SHA-1, SHA-2 family, SHAKE-256)
* Asymmetric keys: RSA, DSA, EC
* Elliptic curves — short-Weierstrass, twisted Edwards (Ed25519, Ed448), Montgomery (X25519, X448)
* EdDSA and XDH key exchange
* PEM, ASN.1 BER / DER, X.509 certificates
* SRTP and TLS ciphersuite tables

### Binary formats
* ELF, Mach-O, and PE / COFF parsers

### Tooling
* Test framework — asserts, fixtures, loop / stress / fuzzy / bench tiers, timeout detection, fork isolation
* Command-line argument parser with grouped options and sub-commands
* Logging framework with colour-aware terminals

Getting the code
--------
Currently you'll find the code @ [github](https://github.com/haaspors/rlib) (https://github.com/haaspors/rlib)

Dependencies
--------
* A C compiler — gcc, clang or MSVC. Other C99-capable compilers should work but aren't routinely tested.
* [meson](https://mesonbuild.com) and a backend — typically [ninja](https://ninja-build.org).

Building
--------
rlib uses [meson](https://mesonbuild.com). Configure, build, test and install:

```sh
meson setup build
meson compile -C build
meson test -C build
meson install -C build
```

`build` is the conventional name for the build directory — any name works, and you can keep several side-by-side build directories with different options.

### Build types

Pass `--buildtype=<type>` to `meson setup`:

| Build type        | Flags          | Notes      |
| ----------------- | -------------- | ---------- |
| `debugoptimized`  | `-g -O2`       | default    |
| `debug`           | `-g`           | no opt     |
| `release`         | `-O3`          | no debug   |
| `plain`           | (none)         | you supply `CFLAGS` |

```sh
meson setup build-release --buildtype=release
meson compile -C build-release
```

### Build options

rlib exposes feature toggles in [`meson_options.txt`](meson_options.txt) (threads, modules, signals, files, sockets). Set them at configure time with `-D<option>=<value>`, or change them later with `meson configure`:

```sh
meson setup build -Denable_sockets=false
meson configure build -Denable_threads=false   # reconfigure existing build dir
```

`meson configure build` with no arguments lists every option and its current value.

### IDE project files

Meson can generate Visual Studio or Xcode project files via `--backend=vs` / `--backend=xcode`. See the [meson docs](https://mesonbuild.com/Running-Meson.html#backend-options) for the full set.

