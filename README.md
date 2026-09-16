# hermes-bundle-forensics

`hbcinfo` reads a Hermes bytecode file and tells you where its bytes went.

On a 770 KB test bundle: **28.1% string storage, 22.6% debug info, 45.6% bytecode
and tables.** Metro tells you the bundle is 770 KB. It does not tell you that
almost a quarter of it is debug info you probably ship by accident.

```
$ hbcinfo index.android.bundle
file             index.android.bundle
size             769750 bytes
version          96
source hash      63d94f00108473a029df7a8b9bd61830503f6941
options          staticBuiltins=false cjsResolved=false hasAsync=true

counts
  functions          3004
  strings            6716  (identifiers 3011, overflow 0)
  bigints            0
  regexps            200
  CJS modules        0
  function sources   1

section map
  header                                  128    0.0%
  string storage                       216423   28.1%
  array buffer                          12497    1.6%
  obj key buffer                            5    0.0%
  obj value buffer                       5000    0.6%
  regexp storage                         9690    1.2%
  bigint storage                            0    0.0%
  debug info                           174366   22.6%
  footer                                   20    0.0%
  rest (tables + bytecode)             351621   45.6%
```

## Why

Every React Native team eventually asks "why is our bundle this big, and what
do we cut?" The usual answers stop at the JavaScript layer — source-map
explorers, Metro's module graph. But the artifact that actually ships is
Hermes bytecode, and its cost distribution does not match the JS source's.
A 40-character string costs the same in the string table whether it came from
one module or forty. Debug info can be a quarter of the file and is invisible
to every JS-level tool.

This reads the shipped artifact directly.

## Scope

**What it reads today:** the 128-byte bytecode file header — every count and
every section size derivable from it, exactly, with no guessing.

**What it does not read yet:** per-function costs. Those require walking the
function header table, which is the next milestone. Until then everything not
derivable from the file header is reported honestly as one `restante` bucket
rather than estimated.

**Bytecode versions 90–96.** Version 96 is current for Hermes as of the
`BytecodeVersion.h` in `facebook/hermes`, and is what React Native ships.
Below 90, fields are missing from the header; the tool refuses rather than
reading garbage.

**Raw HBC files only.** Pulling the bundle out of an `.apk` is not implemented.
Unzip first:

```sh
unzip -p app.apk assets/index.android.bundle > bundle.hbc
```

**Not supported:** delta-prepped bundles (detected and reported, not parsed).

## Build

Requires [Zig](https://ziglang.org/download/) 0.16.0. No other dependencies —
no CMake, no libc, no Visual Studio.

```sh
zig build            # -> zig-out/bin/hbcinfo
zig build test
zig build run -- bundle.hbc
```

## Generating a test bundle

There is no committed fixture — a binary blob in the repo would be one more
thing to keep honest. Build one with the Hermes CLI
([releases](https://github.com/facebook/hermes/releases)):

```sh
hermesc -emit-binary -out bundle.hbc app.js
```

Note that Hermes eliminates top-level bindings that are never read, so a
synthetic test file has to keep its values live or the regexp, array and
object buffers all come back zero.

## Where the layout comes from

`include/hermes/BCGen/HBC/BytecodeFileFormat.h` in `facebook/hermes`. The
struct is `LLVM_PACKED`, but every field happens to land on a naturally
aligned offset, so the header is just a run of little-endian integers.

The parser reads it field by field instead of casting to an `extern struct`.
Relying on the compiler's ABI would silently paper over exactly the kind of
layout mismatch this tool exists to catch — and it would make the version
range a lie, since the whole point of `VERSION_MIN`/`VERSION_MAX` is that the
layout is version-dependent.

## Trade-offs

- **Integer percentages, not floats.** Output is byte-identical on every
  platform, which matters if this ever gates a bundle-size check in CI.
- **A truncated file is an error, not a warning.** An earlier version printed
  a section map with percentages over 100% for a truncated bundle. Refusing to
  answer beats answering wrong.
- **No `.apk` support yet.** `unzip -p` is one line and already on everyone's
  machine; a bundled zip reader is not free to maintain.
- **No iOS `.ipa` testing.** Developed on Windows against `.apk` and locally
  compiled bundles. The parser is format-level and should not care, but it has
  not been verified against an `.ipa`, and claiming otherwise would be a guess.

## Roadmap

1. Walk the function header table — per-function bytecode size, and the
   top N functions by cost.
2. Parse the string table and attribute string storage back to entries;
   surface near-duplicates.
3. Read `.hbc` straight out of an `.apk`.
4. Diff two bundles and report what grew.
