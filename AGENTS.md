# AGENTS.md

Notes for coding agents (and humans) changing rlib.
See [README.md](README.md) for the overview and basic build.

## Layout

| Path             | Contents |
| ---------------- | -------- |
| `include/rlib/`  | Public headers by module. `rlib.h` is the umbrella. |
| `rlib/`          | Implementation. `*-private.h` headers are internal. |
| `test/`          | The `rlibtest` suite, plus `test/android` instrumented tests. |
| `bench/`         | Micro-benchmarks. |
| `example/`       | Standalone programs; also the manual check for what unit tests can't assert. |
| `tools/`         | Generators for tables and test vectors. Regenerate rather than hand-edit their output. |
| `cross/`         | meson cross files: mingw-w64 and Android NDK. |

## Build and test

```sh
meson setup _build_linux
meson compile -C _build_linux
meson test -C _build_linux --print-errorlogs
```

- `_build*` directories are git-ignored; keep one per configuration.
- `werror=true` is set: any warning fails the build, on every compiler.
- Run one test with `_build_linux/test/rlibtest -f '/<suite>/<name>'`.
  `-H`, `-i` and `-B` also run `HEAVY_`, `SKIP_` and `BROKEN_` tests.

### CI and local tiers

The mingw-w64 cross build and the Android ARM ABIs are **build-only** in CI.
`HEAVY_RTEST` corpora and Android instrumented tests run only on the daily schedule.
So a green local Linux build is not enough for code that touches platform-specific paths:

```sh
meson setup _build_asan  -Db_sanitize=address,undefined -Db_lundef=false -Dc_args=-fno-sanitize=function
meson setup _build_mingw --cross-file cross/mingw-w64-x86_64.ini
meson setup _build_android_aarch64 --cross-file cross/android-aarch64.ini   # NDK clang on PATH
```

The sanitizer build emits warnings the plain build does not, e.g. `-Wmaybe-uninitialized`.
The mingw build runs under Wine with an `exe_wrapper = 'wine'` cross file overlay,
and the build's `rlib/` and the mingw runtime on `WINEPATH`.
Wine is not Windows for socket, wait and NUMA semantics, so treat it as a smoke test.

## Portability pitfalls

- **MSVC narrowing.**
  MSVC builds at `/W3 /WX`, so implicit narrowing (C4244) is an error there,
  even when gcc, clang and mingw are silent.
  Widen the local variable's type rather than casting at each use.
- **mingw defines both `R_OS_WIN32` and `HAVE_PTHREAD_H`.**
  Gate native vs pthread code with the same condition on the type and on the code using it,
  or mingw mixes Win32 and pthread primitives.
  CI only builds this combination.
- **Config symbols come from `rconfig.h`.**
  A header that tests an rlib config symbol in `#if` must include `<rlib/rtypes.h>` first,
  or the test is silently false.
  This shows up only on MSVC.
- **Windows rtest runs in one process.**
  `fork` is emulated with threads, so whatever a test leaks carries over into later tests.
  Reset every fixture field in `RTEST_FIXTURE_SETUP`,
  and validate Windows changes with the full suite, not a filter.
- **IOCP teardown is asynchronous.**
  Cancelled I/O still completes later;
  drain the loop before dropping the last reference,
  and read `WSAGetLastError()` before calling anything that may clobber it.
- **Android** has no `/tmp` (set `TMPDIR`), no glibc and restricted CPU affinity;
  armv7a is the only 32-bit target, so it guards 32-bit pointer and `time_t` assumptions.

## Code conventions

Follow `.editorconfig` and match the surrounding code.

- Put a space between a function or macro name and its `(`.
- Use rlib's types (`rsize`, `ruint8`, `rboolean`, ...) rather than raw C ones.
- Users include only `<rlib/rlib.h>` or a module umbrella such as `<rlib/rnet.h>`.
- Keep comments minimal.
  Explain the failure mode in the comment itself;
  no issue numbers and no references to other libraries' implementations.
  The longer *why* belongs in the commit message.
- Write Markdown with semantic line breaks.
  Start each sentence on a new line,
  and break a sentence longer than 100 columns at a comma or colon.

### Adding a file

- New source: add it to `rlib/meson.build`.
- New public header: include it from `rlib.h` or the module umbrella.
- New test file: add it to `rlibtest_sources` in `test/meson.build`.

### Documentation

Every new `R_API` symbol gets full Doxygen documentation in the same change,
and a new header gets a `@defgroup` / `@file` block (see `include/rlib/rbase64.h`).
Nested `@{ ... @}` member groups can make Doxygen list typedefs and macros under "Functions";
check the generated HTML when adding groups.

### Implementing standards

Read the actual spec text before choosing types and sentinels:
grammar, defaults, edge values, "absent" vs "zero".
Cite the RFC by number in the header docs.

## Tests

Tests use rlib's own framework (`include/rlib/rtest.h`):

```c
RTEST (rbase64, encode, RTEST_FAST)
{
  r_assert_cmpuint (r_base64_encode (NULL, 0, src, sizeof (src)), ==, 0);
}
RTEST_END;
```

- Prefix a test with `SKIP_` (temporarily disabled),
  `HEAVY_` (correct but too slow for per-PR CI) or `BROKEN_` (known failing).
- Use the typed asserts (`r_assert_cmpuint`, ...) so failures print both values.
- Tests that need the network or privileged ports must degrade cleanly on CI runners,
  and on non-root Android.

## Commits and pull requests

- Title: `<module>: <what changed>`, e.g. `net/srtp: reject mixing EKT and MKI on one context`.
  Not conventional-commit prefixes (`feat:`, `fix:`).
- One commit per feature or fix; split multi-feature branches rather than squashing.
- Body: what changed and the reason that matters, concisely.
  Put long investigation narratives in the PR description.
- To close an issue,
  put `Closes #N` as the last line of the body of *each* fixing commit (one keyword per issue),
  never in the title.
  Don't write negated forms like "does not close #N": GitHub still closes it.
- No test counts, and no "follow-up filed as #X" lists, in commits or PRs.
- Undo an earlier commit with `git revert`, not a hand-written inverse.
- PR descriptions don't repeat the commit list.
