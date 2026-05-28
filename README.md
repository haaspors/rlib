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
* Threads
* Atomic operations
* Clock/Timestamp
* Socket/Networking
* Buffers/Memory chunks abstraction through RMemAllocator
* Log framework
  * Nice colors in supported text terminals (not on windows (cmd.exe))
* Test framework
  * Nice assert framework
  * Easy test declaration
  * Detects crashes (`SIGSEGV ++`)
  * Detects timeouts
  * Forks tests on platforms where `fork()` is supported
* Command line option parser
* Multiple/Arbitrary precision integer (bignum, BIGINT, big integer) math
* ASN.1
  * BER and DER decoder
* Cryptography
  * Private/Public keys
  * Ciphers
* Threadpool
  * Taskqueue
* Event loop - using edge triggered IO events
  * KQueue on BSD/Darwin
  * Epoll on Linux
  * IOCP on Windows
* ELF parser
* more to come ...

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

