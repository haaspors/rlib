# AGENTS.md

Notes for coding agents (and humans) working on rlib. The user-facing
overview, feature list and basic build instructions are in
[README.md](README.md); this file covers what you need to change the code
without breaking a platform you can't see.

## Layout

| Path             | Contents |
| ---------------- | -------- |
| `include/rlib/`  | Public headers, grouped by module (`crypto/`, `net/`, `ev/`, `os/`, ...). `rlib.h` is the umbrella. |
| `rlib/`          | Implementation, same module split. `*-private.h` headers are internal only. |
| `test/`          | The `rlibtest` suite (one `.c` per area) plus `test/android` instrumented tests. |
| `bench/`         | Micro-benchmarks. |
| `example/`       | Small standalone programs; also the manual check for things unit tests can only assert invariants about. |
| `tools/`         | Python generators for tables and test vectors (Unicode, curves, Wycheproof, ...). Regenerate rather than hand-edit their output. |
| `cross/`         | meson cross files: mingw-w64 and Android NDK ABIs. |
| `docs/`          | Doxygen config; output goes to `docs/output/` (ignored). |

## Build and test

```sh
meson setup _build_linux
meson compile -C _build_linux
meson test -C _build_linux --print-errorlogs
```

- Build directories named `_build*` are git-ignored; keep one per
  configuration side by side (e.g. `_build_asan`, `_build_mingw`).
- The build uses `warning_level=2` and `werror=true`: any warning fails
  the build, on every compiler.
- Run the test binary directly to narrow down:
  `_build_linux/test/rlibtest -f '/rbase64/*'` (path is `/<suite>/<name>`).
  `-H` also runs `HEAVY_RTEST_*`, `-i` runs `SKIP_RTEST_*`, `-B` runs
  `BROKEN_RTEST_*`, `-v` is verbose.
- Feature toggles are in `meson_options.txt`. `-Drpoll=enabled` switches
  Windows from the IOCP backend to the WSAEventSelect/poll backend.

### What CI covers

CI (`.github/workflows/ci.yml`) builds and tests on Linux x86-64 and
AArch64 (gcc, clang), macOS (clang), Windows x64 and ARM64 (MSVC, IOCP
and rpoll), ASan+UBSan and TSan on Linux, and Doxygen. The mingw-w64 cross
build and the Android ARM ABIs are **build-only**; Android x86-64 runs the
suite on an emulator. `HEAVY_RTEST` corpora and Android instrumented tests
run only on the daily schedule.

A green local Linux build is not enough for code that touches
platform-specific paths. Useful local tiers:

```sh
meson setup _build_asan  -Db_sanitize=address,undefined -Db_lundef=false -Dc_args=-fno-sanitize=function
meson setup _build_mingw --cross-file cross/mingw-w64-x86_64.ini
meson setup _build_android_aarch64 --cross-file cross/android-aarch64.ini   # NDK clang on PATH
```

The sanitizer build can emit extra warnings (e.g. `-Wmaybe-uninitialized`)
that the plain build does not; check its compile output too.

The mingw build can also be run under Wine by adding a cross file overlay
with `exe_wrapper = 'wine'` and putting the build's `rlib/` directory and
the mingw runtime on `WINEPATH`. Wine is not Windows for socket, wait and
NUMA semantics, so treat it as a smoke test.

## Portability pitfalls

- **MSVC narrowing.** MSVC builds at `/W3 /WX`, so implicit narrowing
  (C4244, e.g. `rsize` passed as `int`) is an error there even when gcc,
  clang and mingw are silent. Prefer widening the local variable's type
  over sprinkling casts at each use.
- **mingw defines both `R_OS_WIN32` and `HAVE_PTHREAD_H`.** Gate native vs
  pthread code symmetrically (the same condition on the type and on the
  code using it), or mingw will mix Win32 and pthread primitives. No CI job
  runs this combination, only builds it.
- **Config symbols come from `rconfig.h`.** A header that tests an rlib
  config symbol in `#if` (e.g. to pick the event-loop backend or order
  winsock includes) must include `<rlib/rtypes.h>` first, or the test is
  silently false. This shows up only on MSVC.
- **Windows rtest runs in one process.** `fork` is emulated with threads,
  so anything a test leaks (sockets, in-flight overlapped I/O, fixture
  fields) carries over into later tests. Reset every fixture field in
  `RTEST_FIXTURE_SETUP`, don't rely on zero-init. Validate Windows changes
  with the full suite, not a filter.
- **Completion (IOCP) teardown is asynchronous.** Cancelled I/O still
  completes later; drain the loop before dropping the last reference, and
  read `WSAGetLastError()` before calling anything that may clobber it.
- **Android** has no `/tmp` (`TMPDIR` must be set), no glibc and
  restricted CPU affinity; armv7a is the only 32-bit target, so it guards
  32-bit pointer and `time_t` assumptions.

## Code conventions

Follow `.editorconfig` and match the surrounding code:

- C99, 2-space indent, no tabs, 80 columns, braces on the same line.
- A space between a function or macro name and its `(`:
  `r_base64_encode (dst, size, src, len)`.
- Public symbols use the `r_` prefix for functions, `R` for types
  (`RMem`, `RBuffer`) and `R_` for macros. Use rlib's types (`rsize`,
  `ruint8`, `rboolean`, `rpointer`, ...) rather than raw C ones.
- Every source file starts with the LGPL license header.
- Public headers: `__R_FOO_H__` include guard, the
  `#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)`
  guard, and declarations inside `R_BEGIN_DECLS` / `R_END_DECLS`. Exported
  functions are marked `R_API`. Users include only `<rlib/rlib.h>` (or a
  module umbrella such as `<rlib/rnet.h>`).
- Private headers (`*-private.h`) `#error` unless `RLIB_COMPILATION` is
  defined. Sources include `"config.h"` first.
- Keep comments minimal. Explain the failure mode in the comment itself;
  no issue numbers and no references to other libraries' implementations.
  The longer *why* belongs in the commit message.

### Adding a file

- New source: add it to the list in `rlib/meson.build`.
- New public header: include it from `rlib.h` or the module umbrella
  header.
- New test file: add it to `rlibtest_sources` in `test/meson.build`.

### Documentation

Every new `R_API` symbol gets full Doxygen documentation in the same
change: `@brief`, `@param`, `@return`, and a `@defgroup` / `@file` block
for a new header (see `include/rlib/rbase64.h`). Nested `@{ ... @}`
member groups can make Doxygen list typedefs and macros under
"Functions"; check the generated HTML (`doxygen docs/Doxyfile`) when
adding groups.

### Implementing standards

rlib implements many RFCs and FIPS documents. Read the actual spec text
(grammar, defaults, edge values, "absent" vs "zero") before choosing types
and sentinels, and cite the RFC by number in the header docs.

## Tests

Tests use rlib's own framework (`include/rlib/rtest.h`):

```c
RTEST (rbase64, encode, RTEST_FAST)
{
  r_assert_cmpuint (r_base64_encode (NULL, 0, src, sizeof (src)), ==, 0);
}
RTEST_END;
```

- Type is `RTEST_FAST`, `RTEST_SLOW`, `RTEST_INTEGR` or `RTEST_SYSTEM`;
  it also scales the timeout.
- Variants: `RTEST_F` (fixture), `RTEST_LOOP`, `RTEST_STRESS`,
  `RTEST_BENCH`. Prefix with `SKIP_` (temporarily disabled), `HEAVY_`
  (correct but too slow for per-PR CI) or `BROKEN_` (known failing).
- Use the typed asserts (`r_assert_cmpuint`, `r_assert_cmpstr`,
  `r_assert_cmpmem`, ...) so failures print both values.
- Tests that need the network or privileged ports must degrade cleanly
  on CI runners and non-root Android.

## Commits and pull requests

- Title: `<module>: <what changed>`, e.g. `net/srtp: reject mixing EKT
  and MKI on one context`, `os/proc: ...`, `ci: ...`. Not
  conventional-commit prefixes (`feat:`, `fix:`).
- One commit per feature or fix; split multi-feature branches rather than
  squashing.
- Body: what changed and the reason that matters, concisely. Put long
  investigation narratives in the PR description.
- To close an issue, put `Closes #N` as the last line of the body of
  *each* fixing commit (one keyword per issue), never in the title. Don't
  write negated forms like "does not close #N": GitHub still closes it.
- No test counts, and no "follow-up filed as #X" lists, in commits or PRs.
- Undo an earlier commit with `git revert`, not a hand-written inverse.
- PR descriptions don't repeat the commit list; GitHub already shows it.
