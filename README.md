# hermes-bundle-forensics

`hbcinfo` reads a Hermes bytecode bundle, from an `.apk`, `.aab`, `.ipa` or a
raw `.hbc`, and tells you where its bytes went.

It found this on a real shipped app, comparing the Android and iOS artifacts of
one build:

```
  debug info                         28      1722956   +1722928
```

The iOS bundle is 1.93 MB larger than the Android one, and **1.72 MB of that is
Hermes debug info the release build kept**. Metro reports one bundle size per
platform and stops there; nothing in the JS toolchain points at the line above.

The cause is a default that differs by platform. `-output-source-map` moves the
debug info out of the bundle and into the `.map`, and React Native passes it on
one platform but not the other:

| | flag | debug info in the shipped bundle |
|---|---|---|
| Android, `ReactExtension.kt` | `["-O", "-output-source-map"]`, always | 28 bytes |
| iOS, `react-native-xcode.sh` | `-output-source-map` only when `SOURCEMAP_FILE` is set | everything |

Compiling one file both ways with the same `hermesc` shows the mechanism
directly: 208 bytes of debug info without the flag, 28 with it, and a `.map`
alongside.

So the fix is not to strip anything. Set `SOURCEMAP_FILE` in the iOS build and
you get a source map for symbolication *and* drop the bytes, because Sentry and
Crashlytics read the `.map`, not the section inside the bundle.

## What it reports

```
$ hbcinfo --top 5 app-release.aab
file             app-release.aab!base/assets/index.android.bundle
size             3846124 bytes
version          96
source hash      693b31b7a9443b1157c95ef47b4d5e85c7d2fc8e
options          staticBuiltins=false cjsResolved=false hasAsync=false

counts
  functions          19360
  strings            39148  (identifiers 24540, overflow 305)
  bigints            0
  regexps            279
  CJS modules        0
  function sources   79

functions
  distinct bodies    15305
  bytecode bytes     2191175
  shared bodies      4055 headers reuse a body, saving 80467 bytes
  overflowed headers 4

strings
  storage buffer     838954 bytes
  sum of lengths     1028481 bytes
  packer overlap     189527 bytes saved (18.4%)
  utf-16 strings     808  (63536 bytes, 2 per code unit)
  overflowed entries 305

section map
  header                                  128    0.0%
  function headers                     309760    8.0%
  string kinds                             12    0.0%
  identifier hashes                     98160    2.5%
  string table                         156592    4.0%
  overflow string table                  2440    0.0%
  string storage                       838954   21.8%
  array buffer                          50616    1.3%
  obj key buffer                        46797    1.2%
  obj value buffer                     109440    2.8%
  bigint storage                            0    0.0%
  regexp storage                        26212    0.6%
  function bytecode                   2191175   56.9%
  debug info                               28    0.0%
  footer                                   20    0.0%
  rest (info + padding)                 15790    0.4%

top 5 functions by bytecode size
     58103 bytes  #0       params 1   frame 21   global
     21968 bytes  #18782   params 8   frame 20   (anonymous)
     20587 bytes  #18323   params 8   frame 15   (anonymous)
     11614 bytes  #16274   params 1   frame 89   GameScreen
      8907 bytes  #15901   params 1   frame 60   GameSetupScreen

top 5 strings by size
     30484 bytes  #14803   utf16 ᵁ<Õı...
      7986 bytes  #10373         function decorateAnimation_reactNativeReanimated_utilTs8(ani...
      7240 bytes  #12263         function reactNativeReanimated_springTs2(toValue,userConfig,...
      5021 bytes  #12408         function withStyleAnimation_reactNativeReanimated_styleAnima...
      4761 bytes  #12259         function reactNativeReanimated_springTs1(){const{GentleSprin...
```

Two things in that output are worth a second look.

**`rest` is 0.4%.** Everything else is attributed to a named section, derived
from the file rather than estimated. When a number here is wrong it is wrong
loudly, not quietly folded into a remainder.

**The largest strings are Reanimated worklets**, shipped as their own source
text so the UI-thread runtime can re-evaluate them. That is how the library
works, but it means a chunk of the string table is JavaScript source in a
bundle that is otherwise compiled.

## Diffing two bundles

The question teams actually ask is not "how big is this" but "what grew".

```
$ hbcinfo app-release.aab app-release.ipa
```

Sections and counts line up exactly, and the section deltas sum to the total
delta. If they ever stop doing that, something is being double-counted.
Functions are matched by name, which only works for names unique to both
bundles; the report says how many it could not match rather than pretending
the rest vanished.

## Install

Prebuilt binaries for linux, macOS and Windows, on x86_64 and aarch64, are on
the [releases page](https://github.com/brunozampirom/hermes-bundle-forensics/releases).
Each release ships a `SHA256SUMS` file.

```sh
tar -xzf hbcinfo-v0.1.0-aarch64-macos.tar.gz
./hbcinfo-v0.1.0-aarch64-macos/hbcinfo app-release.aab
```

## Usage

```
hbcinfo [options] <file> [file-b]

  --top N        list the N largest functions and strings (default 10, 0 skips)
  --entry PATH   which bundle to read, when a container holds several
  --entry-b PATH same, for the second file in a diff
  --list         list the bundles in a container and exit
```

Containers are detected by the `PK\x03\x04` signature, not by extension. A
container holding several bundles (split APKs, multi-module AABs) is an error
rather than a silent pick, since which one the numbers describe would otherwise
be a guess.

## Scope

**Bytecode versions 90-99**, across the two lines that are actually in the wild.

`facebook/hermes` main tops out at **96**. React Native does not ship that one:
since Hermes V1 became the default it ships the `static_h` line, which emits
**98** and up. They disagree about more than a version number:

| | classic (90-96) | `static_h` (97+) |
|---|---|---|
| file header | 21 fields | one more, `numStringSwitchImms`, so everything after the object shape table sits four bytes later |
| third literal section | `objValueBufferSize`, a byte count | `objShapeTableCount`, an entry count of 8 bytes each |
| function header entry | 16 bytes | 12 bytes; the word holding `infoOffset` is gone |
| inline function name | 17 bits | **8 bits** |
| overflow offset | `(infoOffset << 16) \| offset` | `(functionName << 24) \| offset` |

That 8-bit name field has a visible consequence: any function whose name is not
in the first 256 strings cannot fit inline, so on a real bundle almost every
header overflows. On the React Native bundle measured below, 6667 of 7482 did,
and the full size headers they point at are 12.9% of the file. They get their
own row rather than disappearing into the remainder.

Below 90, fields are missing from the header; the tool refuses rather than
reading garbage.

**Not supported:** delta-prepped bundles (detected and named, not parsed).
Diffing across the two lines is refused, since the section tables do not line
up and a row would be labelled from one side and filled from the other.

To get a 96 bundle out of a recent React Native, build with
`RCT_HERMES_V1_ENABLED=0`.

**What it does not do:** attribute bytes back to JS modules. Hermes keeps no
module boundary in the bytecode, so anything module-level would have to come
from a Metro source map, which is a different tool.

## Build from source

Requires [Zig](https://ziglang.org/download/) 0.16.0. No other dependencies:
no CMake, no libc, no Visual Studio.

```sh
zig build            # -> zig-out/bin/hbcinfo
zig build test
zig build run -- bundle.hbc
```

## Where the layout comes from

`include/hermes/BCGen/HBC/BytecodeFileFormat.h` in facebook/hermes, read on both
branches: `main` for the classic line and `static_h` for the one React Native
ships. Plus `BytecodeStream.cpp` for section order and alignment. Section order
follows `visitBytecodeSegmentsInOrder()`, and each section is preceded by
`pad(BYTECODE_ALIGNMENT)`, so each starts on the next 4-byte boundary.

Everything is parsed field by field rather than cast from an `extern struct`.
Relying on the compiler's ABI would paper over exactly the layout mismatches
this tool exists to catch, and it would make the supported version range a lie,
since the whole point of that range is that the layout is version-dependent.

Three details in the format are easy to read wrong, and each has its own test:

- A `SmallFuncHeader` that overflows stores the large header's offset split
  across two of its own fields: `(infoOffset << 16) | offset` on the classic
  line, and `(functionName << 24) | offset` on `static_h`, which has no
  `infoOffset` to borrow.
- A string entry with `length == 0xFF` is overflowed, and its `offset` field is
  then an **index into the overflow table**, not a byte offset.
- Summed string lengths exceed the storage buffer on every real bundle. That is
  not corruption: Hermes lays strings out with a suffix array so a string that
  is a suffix of another shares its bytes. Measured at 18.4% above.

## Trade-offs

- **Integer percentages, not floats.** Output is byte-identical on every
  platform, which matters once this gates a bundle-size check in CI.
- **A truncated file is an error, not a warning.** An earlier version printed a
  section map with percentages over 100% for a truncated bundle. Refusing to
  answer beats answering wrong.
- **Deduplicated function bodies are counted once.** Hermes shares identical
  bodies between headers, so summing every function's size overcounts, by
  80 KB on the bundle above.
- **The container path has no unit tests.** Its pure helpers do; the zip reading
  itself is covered by an end-to-end check that reading from a container gives
  output identical to unzipping first. Building zip fixtures in-process was not
  worth the code.
- **Validated on two apps' real artifacts**: a matching `.aab` and `.ipa` from
  one build (bytecode 96), and a React Native 0.86.3 release bundle (bytecode
  98, where debug info came to 16.9%), plus synthetic bundles from `hermesc` on
  both lines. Not yet run across a corpus.

## Generating a test bundle

No fixture is committed; a binary blob in the repo is one more thing to keep
honest. Build one with the Hermes CLI
([releases](https://github.com/facebook/hermes/releases)):

```sh
hermesc -emit-binary -out bundle.hbc app.js
```

Hermes eliminates top-level bindings that are never read, so a synthetic test
file has to keep its values live or the regexp, array and object buffers all
come back zero.
