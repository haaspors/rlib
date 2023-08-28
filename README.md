rlib [![Build Status](https://travis-ci.org/haaspors/rlib.svg?branch=master)](https://travis-ci.org/haaspors/rlib) [![Appveyor Status](https://ci.appveyor.com/api/projects/status/github/haaspors/rlib?branch=master&svg=true)](https://ci.appveyor.com/project/haaspors/rlib) [![Coverity Status](https://scan.coverity.com/projects/6732/badge.svg)](https://scan.coverity.com/projects/ieei-rlib) [![License](https://img.shields.io/badge/license-LGPL-blue.svg)](https://github.com/haaspors/rlib/blob/master/LICENSE) [![Gitter](https://badges.gitter.im/rliborg/Lobby.svg)](https://gitter.im/rliborg/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
========
rlib is a c library which contains abstractions for OS, platform and CPU architecture.
It's a convenience library for useful things. :-)

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
You'll obviously need your development environment including a c compiler.
* clang
* gcc
* msc
* icc (not tested)
* ...

Also you'll need [python](https://www.python.org) for running the build system.

Building
--------
rlib uses [meson](https://mesonbuild.com) as build system.
Meson supports multiple backends, but you'll most likely use `ninja`.
You can also make meson generate Visual Studio or XCode project files if you like.
See more on that on the meson build system project website!

To configure and build run (`_build_` is output build directory):
```
meson setup _build_
ninja -C _build_
```
To run unit tests:
```
ninja -C _build_ test
```
To install rlib to prefix (E.g. ):
```
ninja -C _build_ install
```

### Build step by step

#### Configure
The configure step is only needed to run once, to generate the appropriate build environment.
This is basically a step to detect what and how to build stuff for your os/platform/cpu.
```
meson _build_
```

#### Build
There are multiple defined build types.
* debugoptimized - (default) debug symbols and some optimizations (`-g -O2`)
* debug - includes debug symbols and no optimization (`-g`)
* release - no debug symbols and some optimizations (`-O2`)
* ...

So to configure and build release:
```
meson --buildtype release _build_
```

#### Test
rlib has a testsuite obviously. After configuring, just run:
```
ninja -C _build_ test
```

