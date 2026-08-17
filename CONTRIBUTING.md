# Contributing to Abyss

## Ground rules

These come directly from the project's malware-safety rules and apply to
every contribution:

- **Never execute, `require()`, `import()`, `eval()`, or otherwise
  interpret a malicious fixture.** Every test fixture is read as raw
  bytes/text only.
- **Every malicious/adversarial fixture file uses a `.sample` suffix**
  (e.g. `polinrider-v1-marker.js.sample`, `temp-auto-push.bat.sample`), so
  it can never be accidentally double-clicked, `require()`d, or picked up
  by a build tool as live config.
- **Do not add a dependency** that violates the v0.1 constraints: no
  npm/Node/Python/Rust/Go runtime dependency, no vcpkg/Conan package, no
  third-party JSON/YAML/security SDK, no Catch2/GoogleTest (use
  `tests/test_harness.h`). CMake must not download anything
  (`FetchContent`, `find_package` for third-party code, etc.).
- **Never clone a known-infected repository or download a live malware
  sample** as part of development or testing.
- **Before porting code from another project**, read its actual license
  file (not just a README claim), and record the source, license, and what
  was reused in a comment at the point of use (see the attribution note in
  `rules/core/thresholds.rules` for the existing example). If no clear
  license exists, use only conceptual/behavioral knowledge — do not copy
  implementation code.

## Building

Requires MSVC (Visual Studio 2022 Build Tools or full IDE) and CMake on
Windows for this milestone (Linux/macOS are future platforms, see
`README.md`).

```
cmake -S . -B build -G Ninja
cmake --build build
./build/abyss_tests.exe
```

(Any CMake generator MSVC supports works; Ninja is just fast. Run from a
"Developer Command Prompt" / after `vcvarsall.bat`, or point
`CMAKE_MAKE_PROGRAM`/`CC`/`CXX` at your toolchain explicitly.)

## Adding a detection rule

If it's a **literal known signature** (a string, hash, or filename): add a
`[rule]` block to the relevant file under `rules/campaigns/` (or a new
campaign file — no code change needed). See `README.md` for the
schema.

If it's **structural/behavioral logic** (anything requiring more than a
literal substring/filename match — parsing, arithmetic, decoding): it
belongs in `src/scanner` (or `src/git`/`src/vscode` for their respective
domains) as native code, with any tunable numbers exposed via
`rules/core/thresholds.rules` rather than hard-coded. See
`README.md` for why this split exists.

Either way: add both a positive fixture (triggers the detector) and, where
a plausible false positive exists, a negative fixture (legitimate content
that must NOT trigger it) under `fixtures/`, and a test in `tests/` for
both. Section 48/49 of the project spec and `README.md`'s
false-positive philosophy are the bar: when a false positive is found, fix
the evidence model — don't just delete the test.

## Adding an execution surface

Add an `[execution-surface]` block to `rules/execution-surfaces/*.esr` —
no code change needed. See `README.md`.

## Tests must pass and the repo must self-scan cleanly

`abyss_tests.exe` must pass, and `abyss scan .` against the repository
root should produce no findings outside of `fixtures/` (intentional),
`rules/campaigns/` (rule packs legitimately contain the literal IOC
strings they detect), and self-referential matches in the detector source
itself (a detector's source code necessarily contains the strings it
searches for, e.g. `"eval("` appearing in an indicator list) — see the
milestone report in the project history for the current baseline. If you
introduce a *new* self-scan finding outside those categories, either fix
the underlying issue or document why it's an accepted self-reference.
