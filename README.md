rlib [![Build Status](https://travis-ci.org/ieei/rlib.svg?branch=master)](https://travis-ci.org/ieei/rlib) [![Appveyor Status](https://ci.appveyor.com/api/projects/status/github/ieei/rlib?branch=master&svg=true)](https://ci.appveyor.com/project/ieei/rlib) [![Coverity Status](https://scan.coverity.com/projects/6732/badge.svg)](https://scan.coverity.com/projects/ieei-rlib) [![License](https://img.shields.io/badge/license-LGPL-blue.svg)](https://github.com/ieei/rlib/blob/master/LICENSE) [![Gitter](https://badges.gitter.im/rliborg/Lobby.svg)](https://gitter.im/rliborg/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
========
rlib is a c library and contains abstractions for OS, platform and CPU architecture.
It's a convenience library for useful things. :-)

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
* Threadpool
  * Taskqueue
* Event loop - using edge triggered IO events
  * KQueue on BSD/Darwin
  * Epoll on Linux
  * IOCP on Windows
* more to come ...

Getting the code
--------
Currently you'll find the code @ [github](https://github.com/ieei/rlib) (https://github.com/ieei/rlib)

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
rlib uses [waf](https://waf.io) as build system.

To configure and build both debug and release build, and then install:
```
python waf configure buildall install
```

### Build step by step

#### Distclean
Dist clean will clean all configuration, build and cached files.
```
python waf distclean
```

#### Configure
The configure step is only needed to run once, to generate the appropriate build environment.
This is basically a step to detect what and how to build stuff for your os/platform/cpu.
```
python waf configure
```

#### Build
There are two defined variants you can build.
* release - (default) no debug symbols and some optimizations (`-O2`)
* debug - includes debug symbols and no optimization

The following will build the default variant:
```
python waf build
```
which is equivalent to:
```
python waf --variant=release build
```
To build debug only:
```
python waf -d build
```
or
```
python waf --variant=debug build
```
To build all variants:
```
python waf buildall
```

#### Clean
Clean all buildfiles. Could be used if you want to force rebuilding without reconfiguring.
```
python waf clean
```

#### Test
rlib has a testsuite obviously and you can both build and run the test with the test command. This is essentially the
same as build, so running debug variant add `-d`. (But there is no `testall` command)
```
python waf test
```

