# Abyss

**A free, open-source, dependency-free C++ platform for detecting and
recovering from developer supply-chain attacks** — malicious VS Code
tasks, poisoned build configs, fake-font payloads, blockchain C2, and Git
history propagation, generalized beyond any single campaign.

```
DETECT · FORENSICS · RECONSTRUCT · RECOVER · PROTECT
```

## Getting started with the downloaded release

Abyss is **one executable with no installer**. It does not add itself to
`PATH`, does not write itself into the registry, does not register a Start
Menu entry, and does not require administrator rights except for the one
command that installs a Windows service (`abyss protect` — see
[Persistent protection](#persistent-protection)). Downloading and running
it never modifies your environment variables; nothing "puts commands in
PATH" automatically.

The release ZIP contains `abyss.exe` next to a `rules/` folder, `LICENSE`,
`README.md`, `SECURITY.md`, and `SHA256SUMS.txt`. **Keep all of it in one
folder** — `abyss.exe` looks for `rules/` beside itself; separating them
makes every scan report `INCOMPLETE` (see [Rule trust](#rule-trust)).

Before running it, verify the download matches the published hash, then
verify the rule pack it shipped with is intact:

```powershell
Get-FileHash .\abyss.exe -Algorithm SHA256
.\abyss.exe rules verify
.\abyss.exe check
```

Compare the `Get-FileHash` result against the matching line in
`SHA256SUMS.txt`. `rules verify` checks every rule file's hash against
`MANIFEST.sha256` and the compiled trust anchor; `check` is a broader
environment/rule-trust sanity check.

There are two ways to actually run it — no PATH setup needed for either:

1. **Double-click `abyss.exe`.** This opens the interactive menu (see
   [Double-click interface](#double-click-interface) below) — scanning,
   cleaning, safe clone/pull, and protection are all reachable from there
   without typing a single command. This is the path for someone who "only
   downloaded the .exe."
2. **Open a terminal in that folder** — in File Explorer, Shift+right-click
   inside the folder and choose "Open PowerShell window here" (or `cd` to
   it manually) — then run commands prefixed with `.\`, for example:

   ```powershell
   .\abyss.exe scan .
   .\abyss.exe clone https://github.com/owner/repository.git C:\dev\repository
   ```

   The `.\` tells PowerShell/cmd to run the executable sitting in the
   current folder, exactly like any other Windows program without an
   installer. If you'd rather type `abyss` from any folder, you can
   manually add its folder to your own user `PATH` (Windows Settings →
   Environment Variables) — Abyss itself never does this for you, and
   never needs to.

If your terminal is inside the *project* you want to scan instead of
inside Abyss's own folder — a very normal thing to do — see
[GUIDELINES.md](GUIDELINES.md) for exactly what to type in that case, and
for a full per-command reference of what each command needs.

## What Abyss is — and is not

Abyss **is**: a local static-analysis, containment, and recovery tool for
developer repositories, VS Code workspaces, installed extensions, and the
Windows persistence locations developer-supply-chain attacks abuse — with
an explicit, honest exit-code contract you can script against, a growing
set of obfuscation-aware detectors that don't depend on an attacker never
changing a literal string, and transactional quarantine you can inspect
and roll back.

Abyss **is not**: a guarantee that a machine or repository is clean, or a
replacement for antivirus/EDR. It does not have historical process or
network telemetry from before it was installed, and it never deletes or
reinstalls Windows, uploads source code, or transmits credentials. See
[Current, verified limitations](#current-verified-limitations) — every
command below is either real and tested, or explicitly marked as not
implemented; nothing in this project silently pretends to succeed.

## Why — the threat model

Modern developer-targeted attacks don't need a traditional `.exe`. They
abuse the fact that ordinary developer actions — opening a folder in VS
Code, running `npm install`, running `npm run build` — are not perceived
as code-execution events, even though `next.config.js`, `.vscode/
tasks.json`, and `package.json` lifecycle scripts all run arbitrary logic
during those actions. Abyss protects the boundary between
**repository-controlled content** and **the developer tooling that
executes it**.

Its initial deeply-supported threat is **PolinRider** and related
campaigns — a documented, actively-rotating developer-supply-chain
campaign. The detection engine is deliberately campaign-independent:
literal indicators live as data in `rules/campaigns/*.rules`; the
detection *logic* is native C++ that targets the underlying techniques
(concealment, execution-surface abuse, Git history rewriting,
obfuscation shapes) so a rotated variant with new strings still gets
caught.

### The PolinRider pattern, safely explained (no executable payload reproduced anywhere in this repository)

1. **Delivery** — a compromised npm package, a compromised maintainer
   account, or a fake take-home coding test delivers a payload as either
   (a) obfuscated JavaScript appended to a build tool's config file
   (`postcss.config.mjs`, `tailwind.config.js`, `next.config.*`), or (b) a
   `.vscode/tasks.json` with `runOn: folderOpen` that executes silently the
   moment the folder is opened.
2. **Concealment** — the payload is hidden after hundreds of whitespace
   characters on one line (past what a diff viewer renders), or shipped as
   a `.woff2`/`.woff` file that is actually JavaScript with no valid font
   header.
3. **Obfuscation** — a shuffle-table obfuscator assigns a campaign marker
   via a pattern like `global['<key>']='<value>'` (observed key/value
   pairs have rotated at least three times across tracked variants) and
   reaches `eval`/`Function` indirectly to avoid a literal, greppable
   token.
4. **Command and control** — rather than a blocklistable server, some
   variants resolve C2 addresses through public blockchain transactions
   (TRON/BSC/Aptos/Ethereum), which can't be taken down the way a domain
   can.
5. **Propagation** — a local batch script reads the previous commit's
   timestamp, rolls the system clock back, amends the commit, restores the
   clock, and force-pushes — making the malicious commit's timestamps
   consistent with history that predates the attack. This is why Abyss
   treats `GIT_HISTORY_TIME_MANIPULATION` as its own first-class,
   Critical-severity finding (see below).
6. **Why single-point remediation fails** — the propagation script runs
   with the developer's own cached credentials, so a still-poisoned
   repository the developer retains push access to restarts the cycle even
   after a password reset. Full recovery requires checking every local
   repository, not just the one that triggered a review — see
   [Manual credential recovery](#manual-credential-recovery-abyss-cannot-do-this-part-for-you).

## What it detects today

- **Structural checks**: magic-byte validation for WOFF/WOFF2/TTF/OTF/PNG/
  JPEG/GIF/PDF/ZIP/PE, plus shallow structural validation (declared-length,
  table/section-count sanity) for WOFF2 and PE specifically — catching
  both "no valid header at all" and the sneakier "valid header, script
  appended past the declared length" fake-font pattern. ZIP structural
  validation is deliberately magic-bytes-only — see Limitations.
- **Concealment**: the whitespace-gap technique that hides a payload past
  a diff/editor's visible width; invisible Unicode (zero-width characters,
  bidi-override controls, variation selectors, private-use code points).
  Padded Markdown table rows (`.md`/`.markdown` files only) are exempt from
  the whitespace-gap check — column-aligned tables are shape-identical to
  the concealment technique, and node_modules documentation is full of
  them; without the exemption, most third-party READMEs would falsely
  report Critical findings.
- **Obfuscation-aware, rotation-tolerant detection** (`src/scanner/
  deobfuscate.cpp`): rather than only matching literal known-bad strings,
  Abyss performs bounded, **non-executing** static decoding — base64,
  `\xNN`/`\uNNNN` escapes, percent-encoding, and the
  `'literal'.split('').reverse().join('')` idiom — and checks whether the
  *decoded* content reveals a dynamic-execution keyword (`require(`,
  `child_process`, `eval(`, etc.) that isn't visible in the raw text. It
  also matches the structural *shape* of a `global[<key>]='<value>'`
  campaign-marker assignment independent of the exact property name or
  value, so a rotated marker (confirmed: property names have varied
  between `'!'` and `'_V'`, values between `8-270-2`/`9-3800-1`/`9-6187`
  and `A9-3800-1`/`A9-6187`) is still caught by shape. Every decode
  operation has explicit input/output-size and operation-count bounds —
  nothing decoded is ever passed to `eval`, `Function`, a shell, or any
  interpreter, in this process or any other.
- **Behavioral heuristics**: escape-sequence density, unbroken long
  tokens, high-entropy lines, `constructor.constructor` primitive access,
  indirect `require()` access, `String.fromCharCode` construction, and —
  the highest-signal one — a network capability plus a dynamic execution
  sink in the same file.
- **VS Code task risk**: `.vscode/tasks.json` and `*.code-workspace`
  parsed as inert JSONC, following `dependsOn` task-dependency chains and
  platform (`windows`/`linux`/`osx`) overrides, flagging `runOn:
  folderOpen` automation with real execution content — hidden tasks score
  higher, but a visible one still isn't free. Token-based command
  analysis distinguishes `node font.woff2` (real execution) from `echo
  font.woff2` (a harmless label/echo) and from `./node_modules/.bin/x`
  (a path containing "node", not an invocation of it).
- **VS Code extensions**: installed-extension manifests inspected for
  unconditional broad activation with no declared contribution, and
  entry-point path traversal — read as data only, never activated.
- **Git propagation pattern**: a real command tokenizer (not fragile
  substring matching) — handles comments (`rem`/`::`/`#`), `echo`d
  documentation/examples, quoted arguments, caret line-continuation, and
  `&`/`&&`/`|`/`;` batch separators — recognizing every documented
  force-push flag form (`-f`, `-u -f`, `-f -u`, `-uf`, `-fu`, `--force`,
  `--force-with-lease`) combined with `commit --amend`, classic
  `date`/`time` clock changes (not just PowerShell `Set-Date`), identity
  spoofing, and `.gitignore` artifact-hiding — filename-independent, so a
  renamed copy of a propagation script is still caught. The complete
  documented sequence produces a distinctly labeled
  `GIT_HISTORY_TIME_MANIPULATION` finding at guaranteed Critical/Confirmed.
- **Known IOCs**: literal signatures — obfuscator markers for multiple
  confirmed variants (including one observed first-hand by Windows
  Defender on the Abyss development host, recorded and labeled as such
  rather than conflated with third-party threat intel), decoder
  identifiers, blockchain C2 wallet addresses (TRON and Ethereum) and XOR
  keys, a confirmed fake-font SHA-256 hash, and propagation script
  filenames.
- **Filesystem safety**: symlinks/junctions/reparse points whose target
  escapes the scan root are refused, never read through; a directory-read
  error partway through a walk doesn't abort the rest of it; a file whose
  size/mtime changed between the pre- and post-read stat is flagged as
  unstable (concurrent modification) rather than silently trusted.
- **Execution-surface-aware confidence**: findings inside a file
  autoloaded by a build tool (Next.js, Vite, Astro, ESLint, Babel,
  PostCSS, Tailwind, Webpack, Rollup, Jest, Vitest, Electron Forge, npm,
  VS Code tasks) get a confidence bump — matching an execution surface
  never creates a finding by itself.
- **Credential exposure**: repository file content is checked against the
  same token-shaped patterns used for report redaction (AWS access keys,
  GitHub/GitLab/Slack/OpenAI/Stripe tokens, PEM private-key blocks,
  Authorization headers, `key=value` credential pairs, connection-string
  passwords) and against conventional credential filenames (`id_rsa`,
  `id_ed25519`, `.npmrc`, `.git-credentials`, `.pgpass`). A real
  match is always `REVIEW`, never `Critical`+`Confirmed`, so it is never
  eligible for automatic quarantine, is reported with the exact line
  number, and the finding's own evidence field is passed through the same
  redaction the value would get in any other report, so the credential
  itself is never printed, even in the finding that reports it.

  Several filters run first, none of them naming specific packages —
  they target the *shape* of a non-secret value, which holds regardless
  of which module the text came from: low-character-variety values and
  words like "example"/"changeme"/"placeholder" (a `.env.example` full of
  dummy tokens produces no findings); common documentation-example
  conventions ("someuser", "yourApiKey", "DBHost" — the generic
  `some`/`your`/`my`-prefixed or standalone-generic-word values found
  throughout third-party README files); and, specifically for the generic
  `key=value` pattern (not the fixed-prefix token patterns like
  `gh_`/`AKIA`/`sk-`, which don't have this ambiguity), values that are
  purely alphabetic with no digits at all — a real secret is
  overwhelmingly likely to be high-entropy and contain digits, while a
  value like `getOption`/`someVariable` reads as a variable or function
  reference being matched by the same regex shape as a real assignment,
  not a credential.
- **Host persistence and network correlation** (`abyss system-scan`):
  Registry Run/RunOnce values, Startup-folder items, scheduled-task
  definitions, service binary paths, and PowerShell profile files are read
  as data and checked for launch values associated with this campaign
  family. Running processes are enumerated read-only, and an established
  outbound TCP connection owned by a script-interpreter process
  (`node.exe`, `wscript.exe`, `cscript.exe`, `powershell.exe`, `pwsh.exe`,
  `mshta.exe`) is surfaced for review — Abyss never terminates a process or
  closes a connection based on this data.

No single weak signal is treated as proof. `core.oversized_line`,
`core.long_token`, and `core.high_entropy_line` are each Low/Low on their
own — legitimate minified JS routinely trips all three. Behavioral
findings that combine techniques (obfuscated execution + network +
process-launch) score higher than any single signal, and are kept
separate from campaign *attribution* — a finding can be high-confidence
about a technique while carrying no PolinRider label at all, because the
technique isn't unique to that campaign.

## Verdicts and exit codes

Every command that produces a verdict (`scan`, `preflight`, `open`,
`self-scan`) uses one contract, computed in a single place
(`evidence::computeVerdict`):

| Exit | Label | Meaning |
|---|---|---|
| 0 | `ALLOW` | No compromise detected, coverage was complete, **and** the run used the verified official rule pack |
| 1 | `BLOCK` | A Critical finding was confirmed |
| 2 | `INCOMPLETE` (operational failure) | Rules missing/corrupt/tampered/unanchored, or coverage was incomplete — **never** a clean result |
| 3 | `REVIEW` | High/Medium findings present, or non-official (`--rules`) rules were used — manual review recommended, never presented as an unconditional ALLOW |
| 4 | `UNRESOLVED` | A requested containment/recovery action (`remediate`, `clone`, `pull`, `recover`, ...) did not reach a verified state — distinct from a plain scan `REVIEW`/`BLOCK` |

A Critical finding with only Low/Medium confidence is described as
requiring urgent review, not asserted as a "confirmed compromise" — the
language scales with the evidence's actual confidence, not just its
severity. High/Critical findings can never silently produce exit 0.

`UNRESOLVED` specifically means a quarantine action was actually taken
(`remediate`/`contain --yes`) and the project still isn't clean after that
real change. If nothing was eligible for automatic quarantine in the
first place — every finding stayed below Critical+Confirmed, so nothing
was touched — `remediate`/`contain` reports the scan's own unchanged
verdict (still `BLOCK`, `REVIEW`, whatever it actually is), not a generic
`UNRESOLVED`: nothing being eligible for automation is a different, more
specific fact than "we tried and it didn't work," and collapsing the two
into the same label would misrepresent which one happened.

## Rule trust

Official rules are loaded from **exactly one** deterministic location —
the `rules/` directory installed next to `abyss.exe` — or
`%ProgramData%\Abyss\rules`. There is no parent-directory walking (copying
`abyss.exe` into an attacker-controlled directory tree cannot cause it to
pick up a `rules/` folder several levels up) and the current working
directory / scanned directory is never searched automatically.

Integrity is checked two ways: a SHA-256 manifest (`rules/
MANIFEST.sha256`) covering every shipped rule file, **and** a hash of that
manifest's own bytes compiled directly into the binary
(`src/rules/trust_anchor.h`). The second check is what stops a
self-consistent-but-fake rules+manifest pair from being trusted — an
attacker who can write both a rules directory and a manifest can trivially
keep them matching each other; only an independent expectation baked into
the binary at build time closes that gap. A missing, unreadable,
mismatched, or **unanchored** rule pack is always `INCOMPLETE` (exit 2),
never a silent pass.

`--rules <dir>` (command-line flag only — there is no environment-variable
equivalent) selects an explicit, **untrusted** local rule set for testing
custom rules; every finding it produces is labeled with that trust level,
and it can never produce an official `ALLOW`.

```powershell
.\abyss.exe rules verify      # checks rules/MANIFEST.sha256 and the compiled anchor
.\abyss.exe rules list         # lists every loaded rule and execution-surface entry
```

## Commands

The reference below omits the `.\` / full-path prefix for brevity — see
[Getting started](#getting-started-with-the-downloaded-release) for how to
actually invoke `abyss.exe`, and [GUIDELINES.md](GUIDELINES.md) for exactly
which directory to run each command from.

```
abyss check                          Environment + rule-trust sanity check
abyss scan <path> [--json]           Static scan of one repository or directory
abyss scan-all <parent> [--yes]       Scan every immediate project (and loose file) under a
                                      parent directory, skipping Abyss's own install directory.
                                      With --yes, also quarantines confirmed evidence in every
                                      BLOCKED project (files stored directly in the parent, not
                                      inside a project, are reported but not auto-quarantined —
                                      run `contain` on the parent for those)
abyss system-scan [--json]           Discover and scan repositories, editor extensions and
                                      persistence locations on this PC
abyss preflight <path>               Scan + explicit ALLOW/REVIEW/BLOCK/INCOMPLETE decision
abyss open <path>                    Preflight gate before opening a project (does not launch an editor)
abyss contain <path> [--yes]         Print, or apply, a confirmed-evidence quarantine plan
abyss remediate <path> --yes         Quarantine confirmed evidence, then rescan and verify
abyss verify <path>                  Independent post-remediation scan
abyss quarantine list                List quarantine records (active and restored)
abyss quarantine restore <id> [--force]
                                      Restore a quarantined file, hash-verified first
abyss clone <url> <path>             Stage, scan, then publish a clone (no unsafe checkout)
abyss pull <path>                    Fetch, stage, scan, then fast-forward
abyss protect <path>                 Register a protected root, add Git guards, install the service
abyss unprotect <path>                Remove protection for one root (evidence is preserved)
abyss timeline <path>                Bounded Git commit metadata for investigation
abyss graph <path>                   Bounded decorated Git history graph
abyss recover <repo> <commit> <dest> Materialize and scan a selected commit in a detached worktree
abyss rules list                     List every loaded rule and execution-surface entry
abyss rules verify                   Verify the official rule pack against MANIFEST.sha256 + trust anchor
abyss self-scan                      Verify the rule pack, then scan a staged copy of abyss.exe
abyss status                         Report Abyss's own protection state
abyss version                        Print the Abyss version
```

`abyss open <path>` runs the real preflight gate (the same scan/verdict
logic as `abyss scan`) and reports the decision — it does not launch an
editor for you; it tells you the verdict and lets you decide.

`--yes` confirms an eligible remediation action; `--force` permits a
quarantine restore over an existing path after you have reviewed it;
`--rules <dir>` selects an explicit untrusted local rule set (see
[Rule trust](#rule-trust)).

## Double-click interface

Running `abyss.exe` with no arguments — including double-clicking it from
File Explorer — opens an interactive menu instead of printing usage text.
It is a front end over the same commands above, not a separate
implementation: choose "scan one project" or "scan many projects", paste a
path copied from Explorer (quotes are stripped automatically if present),
and after a scan Abyss offers the relevant next action — clean, verify,
protect, or show the credential-recovery checklist. Safe clone/pull,
quarantine list/restore, system-scan, and protection status are all
reachable from the same menu. Remediation always shows the dry-run plan
first; the menu applies it only after you type `YES` exactly.

### Example

The console shows a short summary — never the full findings list, however
many there are — and points at the full report on disk:

```
$ abyss scan .
Analyzing with 8 worker threads.
Scope: C:\dev\some-project
Verdict: BLOCK (exit code 1)
14 finding(s) — highest severity CRITICAL
Full report: C:\dev\some-project\abyss-results\results.txt
```

The "Analyzing with N worker threads" line (and the live `scanning: X / Y
file(s) analyzed` line while it runs) only appears for scans large enough
to use more than one thread — see
[Performance on large projects](#performance-on-large-projects). It
reports the thread count Abyss is actually running, not a documented
claim; the same number is also recorded in the results file itself
("Worker threads used") for the record.

`abyss-results\results.txt` contains the complete report — rule trust,
telemetry coverage, and every finding with its evidence excerpt, exactly
as detailed as before:

```
ABYSS SCAN REPORT
=================
Scope: C:\dev\some-project

Rule trust:
  Trust level:       official
  Integrity status:  verified

Telemetry coverage:
  Files discovered:        842
  ...
  Git repository detected: YES
  Historical process telemetry: NOT CAPTURED BY THIS SCAN

Result: 14 finding(s) — highest severity CRITICAL
Verdict: BLOCK (exit code 1)
...
```

This is deliberate: hundreds of findings scrolling past a console at
terminal speed reads as alarming and out of control to a developer who
isn't expecting it — easily mistaken for something actively happening to
their machine rather than a static report they can read at their own
pace. `abyss-results/` is written inside whatever directory was scanned
(see [Where results are written](#where-results-are-written)).

Abyss never prints an unqualified "clean" verdict. Every report — on
console and in the results file — states what was actually covered: files
discovered/analyzed/truncated/unreadable, symlinks refused for escaping
the scan root, directory read errors, files that changed mid-scan, and
that historical process/network telemetry from before the scan was not
captured. A scan with incomplete coverage or untrusted/unanchored rules
reports `INCOMPLETE`, never a false-positive-free "clean."

## Where results are written

Every command that would otherwise print a full findings report writes it
to `abyss-results\results.txt` instead, and prints only a short summary
(scope, verdict, finding count, and the file's path) on the console.
`--json` mode is unaffected — JSONL findings still go to stdout, for
scripting. Where the file goes depends on the command:

| Command | `abyss-results\results.txt` location |
| --- | --- |
| `scan`, `preflight`-driven commands, interactive "scan one project" | Inside the scanned project itself |
| `scan-all` | Inside *each* project scanned (loose files directly in the parent get one in the parent itself) |
| `system-scan` | `%ProgramData%\Abyss\abyss-results\` (no single project to write inside) |
| `contain` / `remediate` / `verify` | Inside the project, overwritten by the post-remediation rescan |
| `clone` / `pull` / `recover` | Inside the staged/recovered content — follows it to its final destination on success |
| `self-scan` | Next to the installed `abyss.exe`, not the temporary staging copy |

If the file can't be written (read-only location, permission denied), the
full report is printed on the console instead — a report is never
silently dropped.

Each results file is overwritten by the next scan of the same location.
`abyss-results/` itself is never descended into by a scan, the same way
`.git` isn't — a prior report's own redacted evidence excerpts are text
that can otherwise match the credential/network-exec detectors, so
without this exclusion, re-scanning a project would start reporting
findings about Abyss's own previous report instead of about the project.
If the scanned project is a Git repository, add `abyss-results/` to its
`.gitignore` too — a protected repository's guard hooks (which run
`abyss preflight` on every commit/push, see
[Persistent protection](#persistent-protection)) will otherwise make it
show up as a change after every commit.

## Performance on large projects

`node_modules` (or any vendored dependency directory) is never skipped —
a compromised npm package sitting inside it is exactly the attack shape
PolinRider and similar campaigns use, so excluding it would blind Abyss to
its core threat model rather than just make it faster. A frontend project
with a full dependency tree can easily mean 30,000–50,000+ files.

To keep that honest without being slow, file analysis runs in parallel:
scans of 200 or more files are split across worker threads (smaller scans
stay single-threaded, since thread creation would cost more than it
saves). This changes nothing about *what* is detected — every file still
gets the identical, full analysis — only how many run at once. The
progress line shown during a scan (`scanning: 1200 / 51000 file(s)
analyzed`) reflects real, continuing progress, not a stall.

The thread count is capped by three independent things at once, and the
smallest wins:

- **CPU cores.** More worker threads than logical cores just makes the OS
  time-slice them for this CPU-bound work, which tends to cost more in
  context-switching than it gains.
- **Currently available memory**, queried at scan time (not total RAM —
  what's actually free right now, after whatever else is running). Each
  worker can hold a file up to the 64MB per-file cap plus its decoded copy
  in memory at once in the worst case, so this is what stops a
  memory-constrained machine from being pushed into swapping.
- **A flat ceiling of 15**, regardless of how much memory or how many
  cores are available — I/O and diminishing returns limit the benefit of
  going wider than that for this workload.

There is deliberately no minimum thread count. On a machine where
available memory or core count is genuinely low, running fewer threads —
down to 1 — is correct behavior, not something to override: forcing a
higher floor regardless of measured resources is exactly how a
memory-constrained machine ends up swapping or having the OS kill
processes. (Measured on the machine this was built on, for reference: an
8GB-RAM system with a browser and IDE already open had well under 1GB
actually free — a fixed high thread-count floor would have been unsafe on
that exact, realistic setup.)

## Whole-PC response

```powershell
.\abyss.exe system-scan
```

Discovers, and then scans, repositories under Windows user profiles and
common development roots (`\dev`, `\src`, `\projects`, `\workspace` on
every fixed drive), VS Code extension directories, npm global/cache
directories, and user temp directories — plus the persistence and network
correlation described under [What it detects today](#what-it-detects-today).
Permission failures reduce coverage rather than aborting the scan; run an
elevated terminal for full-machine incident response. Use the repository
path `system-scan` prints with `contain`, `remediate`, and `verify`.

Discovery walks each user profile in full (bounded to 7 directory levels),
the four named development-root names (`dev`/`src`/`projects`/`workspace`)
on every fixed drive, and any other immediate child of a fixed drive whose
name suggests a development folder (contains "code", "dev", "git",
"project", "repo", "source", "src", "workspace", or "work" — so "Big
Projects", "Client Work", and "GitHub Repositories" are all picked up). A
repository nested deeper than that, or under a name matching none of these
patterns, is outside `system-scan`'s discovery and needs `abyss scan
<path>` pointed at it directly. This trade-off is deliberate: an unbounded
full-drive walk on every scan would be slow enough that developers would
stop running it.

If you already know the parent folder holding every project — for example
you keep everything under `E:\Big Projects` — `abyss scan-all` is faster
and more direct than `system-scan`'s discovery walk:

```powershell
.\abyss.exe scan-all "E:\Big Projects"
.\abyss.exe scan-all "E:\Big Projects" --yes
```

The first run scans every immediate project (and any loose file sitting
directly in the parent) and reports a verdict for each. The second form —
`--yes` — additionally quarantines confirmed evidence in every `BLOCK`
project, one at a time, printing each project's own plan and running its
own post-remediation rescan; nothing is quarantined without `--yes`. The
interactive menu's "SCAN MANY PROJECTS" option does the same in two steps:
scan first, then ask `YES`/Enter before cleaning anything. `REVIEW`
findings are never auto-quarantined by either path — heuristic evidence
always needs a human decision, in bulk or one project at a time.

## Cleaning an infected repository

```powershell
.\abyss.exe scan C:\dev\project
.\abyss.exe contain C:\dev\project
.\abyss.exe remediate C:\dev\project --yes
.\abyss.exe verify C:\dev\project
```

`scan` establishes evidence. `contain` (without `--yes`) prints the exact
plan without changing anything. `remediate --yes` quarantines only files
with `Critical` severity and `Confirmed` confidence, then scans again.
`verify` performs a separate, independent scan of the same path. Findings
below `Confirmed` confidence stay `REVIEW` — Abyss does not delete a
legitimate project to resolve uncertainty about one file in it.

## Quarantine and rollback

The default state directory is `%ProgramData%\Abyss` (falls back to a
temp-directory path if `ProgramData` is unavailable). A quarantine record
stores the original path, the protected copy's path, its SHA-256 hash, the
triggering rule, and active/restored state.

The remediation sequence is: hash the source file, copy it into the
protected store, verify the copy's hash matches, commit a journal record,
*then* remove the active file. If any step before the journal commit
fails, the original file is left unchanged — a failure never leaves a file
half-removed.

```powershell
.\abyss.exe quarantine list
.\abyss.exe quarantine restore <record-id>
.\abyss.exe quarantine restore <record-id> --force   # only after reviewing the existing destination
```

Abyss never deletes quarantine automatically.

## Safe clone and pull

```powershell
.\abyss.exe clone https://github.com/owner/repository.git C:\dev\repository
.\abyss.exe pull C:\dev\repository
```

Or, without a command line at all: double-click `abyss.exe` and choose
"Safe clone" / "Safe pull" from the menu (see
[Double-click interface](#double-click-interface)).

**Requires Git for Windows already installed on the machine.** Abyss does
not bundle Git — `clone`/`pull`/`timeline`/`graph`/`recover` locate and run
the real `git.exe` (see below for exactly how); if none is found in a
trusted location, these commands fail with a clear error instead of a
silent no-op. `scan`, `preflight`, `contain`/`remediate`, and everything
else that only reads files do not need Git at all.

Git runs directly via `CreateProcessW` — never through `cmd.exe` or
PowerShell. The `git.exe` used is resolved once from a well-known Git for
Windows install location or an absolute `PATH` entry; **the current
working directory is never part of that search**, specifically so that a
repository shipping its own `git.exe` cannot hijack execution when a
developer runs Abyss from inside that repository (Windows' own implicit
`CreateProcessW` search order checks the calling process's current
directory before `PATH`, which is why this is resolved explicitly instead).

Only `https://` and `ssh://`/`git@`-style remotes are accepted; `file://`
and external-helper (`ext::`) transports are refused. A clone is staged in
a sibling directory with hooks, submodules, and unsafe protocols disabled,
scanned, and published to the requested destination only after `ALLOW`. A
pull scans the current repository first, fetches without touching the
current branch, materializes the fetched commit in a detached worktree,
scans that, and only then fast-forwards — diverged branches are left for
manual review. A repository with an executable Git filter, a custom hook
path, a custom SSH command, or a custom transport program is blocked
before either operation runs — that check tolerates the config file's own
flexible whitespace (`smudge=cmd` and `smudge = cmd` are equally
detected, not just the exact-one-space form). Blocked staging content is
left in place at the path Abyss prints, for investigation.

Pull merges the exact commit SHA that was actually staged and scanned,
resolved once right after `fetch` — not the symbolic upstream name
(`origin/main`) re-resolved at merge time. Fetching and scanning a real
repository can take a while; without pinning the SHA, a second fetch
landing in between (a scheduled task, another terminal) could move the
branch pointer, and the final merge would fast-forward to different,
unscanned content while still claiming to merge what was reviewed. Clone
re-checks that the destination path is still free immediately before the
final publish, not just when staging started, for the same reason —
`fs::rename` replaces an existing path silently, and staging (clone + full
scan) is exactly the kind of long-enough window where something else
could appear there first.

## Persistent protection

```powershell
.\abyss.exe protect C:\dev\project     # run from an elevated (Administrator) PowerShell window
.\abyss.exe status
.\abyss.exe unprotect C:\dev\project
```

`protect` refuses to run until a fresh scan of the project reaches `ALLOW`
— enabling continuous protection on a project that is still `BLOCK`/`REVIEW`
would let the service's own five-second poll quarantine files silently on
its next cycle instead of through a reviewed `remediate --yes`. Once that
passes, `protect` registers the canonical repository path under
`%ProgramData%\Abyss`, installs non-destructive `pre-commit`/`pre-push`
Git hooks (an existing hook is preserved, never overwritten), and installs
and starts the `AbyssProtection` Windows service — administrator approval
is required for the service install. The service rescans registered roots
every five seconds; `Critical`+`Confirmed` findings go through the same
hash-verified quarantine transaction as `remediate`, and every other
result is written to the local protection audit log. `unprotect` removes
protection for one root and stops/removes the service once no protected
roots remain — quarantine and audit evidence are never deleted by this.
`abyss clone`/`abyss pull` are the pre-publication boundary; the
protection service is the second boundary, for changes made through
ordinary `git` commands or other tools outside Abyss.

## Git investigation and recovery

```powershell
.\abyss.exe timeline C:\dev\project
.\abyss.exe graph C:\dev\project
.\abyss.exe recover C:\dev\project <full-commit-hash> C:\recovery\project
```

`timeline` prints bounded commit/parent/author/committer/subject metadata;
`graph` prints a bounded decorated history graph. `recover` requires a
developer-selected, full hexadecimal commit ID (never a branch name or
partial hash, to avoid ambiguity) and materializes it in a detached
recovery worktree, which is then scanned before it is reported as a
verified recovery point. Recovery never rewrites the current branch or
remote history automatically — that stays a deliberate, manual decision.

## Privacy and network behavior

Abyss itself contains no telemetry client and no network code beyond the
`git` subprocess wrapper used by `clone`/`pull`/`timeline`/`graph`/
`recover`. No telemetry, source code, credentials, or findings are
uploaded anywhere, ever, by any command in this build — network access
happens only when you explicitly run a safe clone or safe pull, and only
to the remote you named. Its rule pack is loaded only from its own
installation location (never the directory being scanned, never the
current working directory, never an environment variable) and verified
against a compiled-in trust anchor before use.

## Manual credential recovery — Abyss cannot do this part for you

Abyss does not connect to your GitHub account, does not request a GitHub
token, and does not revoke remote credentials itself — that stays fully
under your control, on official provider interfaces. If a credential
exposure is suspected, work through the applicable steps below **after**
local containment (the machine and repositories have been checked and any
found artifacts preserved as evidence). For each step: know *why* it's
needed and *what risk it removes* before you act, perform the action,
then independently confirm the result — don't just assume it worked.

1. **Windows Credential Manager** (`Control Panel → Credential Manager`,
   or `rundll32.exe keymgr.dll,KRShowKeyMgr`) — review entries related to
   GitHub, Git Credential Manager, npm, and cloud/deploy tooling. Removing
   a cached credential here forces the next Git/npm operation to
   re-authenticate, which is useful *after* you've rotated the underlying
   secret, not as a substitute for rotating it.
2. **GitHub → Settings → Sessions.** Review active sessions and revoke
   anything you don't recognize.
   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/viewing-and-managing-your-sessions
3. **GitHub → Settings → SSH and GPG keys.** Remove any key that existed
   during the suspected compromise window; generate a fresh key only
   *after* local cleanup is complete (a new key generated on a still-
   infected machine is exposed the same way the old one was).
4. **GitHub → Settings → Applications → Authorized OAuth Apps.** Review
   Git Credential Manager, GitHub CLI, and anything unrecognized; revoke
   what you don't actively use.
5. **GitHub → Settings → Installed GitHub Apps.** Same review for App
   installations (broader scopes than OAuth apps in some cases).
6. **Personal access tokens** (fine-grained and classic) — treat every
   token live during the compromise window as exposed; regenerate.
   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
7. **Repository/organization deploy keys** — rotate any deploy key used by
   an affected repository.
8. **Organization/enterprise tokens and self-hosted runners**, if
   applicable — a compromised developer machine that also runs a
   self-hosted Actions runner is a materially larger exposure; involve
   your org admin.
9. **GitHub security log / organization audit log** — review for activity
   you don't recognize in the relevant window.
   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log
10. **npm tokens, cloud provider credentials (AWS/Azure/GCP/etc.), VPS SSH
    keys, and CI/CD secrets** that were accessible from the machine —
    rotate each one at its own provider's official interface.
11. **Issue fresh, least-privilege credentials only after containment and
    independent verification** that the machine and affected repositories
    are clean — a credential minted on a still-compromised machine can be
    exposed the same way.

If you cannot independently verify a step's outcome, treat that step as
**incomplete**, not done — an unverifiable "I think I revoked it" is a gap
to track, not a checked box.

## Interpreting a Windows Defender detection (general guidance)

If Defender (or another AV/EDR product) reports a detection and
"remediation," that is evidence of **detection and a local remediation
action**, not proof the machine, its repositories, its persistence
locations, or any exposed credentials are clean. Distinguish explicitly:

- **Detected** — a specific signature/behavior matched at a specific time.
- **Remediated locally** — an action (quarantine/removal) was attempted
  against the detected artifact.
- **Verified absent after remediation** — an independent rescan confirmed
  the artifact is actually gone (not the same as remediation being
  *attempted*).
- **Remote recovery confirmed** — credentials/sessions/repositories
  affected by whatever the local artifact did have been independently
  checked and rotated where needed (see above).
- **Unknown / unavailable** — anything not directly established by one of
  the above; state it as unknown rather than assuming it's fine.

Abyss does not currently read Defender's detection history or the Windows
Event Log natively (see Limitations) — treat Windows Security's own
Protection History as the authoritative source for what was detected and
what action was actually taken, and correlate manually against any
propagation artifacts (`temp_auto_push.bat`, `temp_interactive_push.bat`,
`config.bat`, `branch_structure.json`) or unexplained `.gitignore`/Git
history changes Abyss's static scan finds in your repositories.

## Installation / build

Windows 10/11, MSVC (Visual Studio 2022 Build Tools or full IDE), CMake,
C++20. No package manager, no internet access required to build — the C++
standard library, Win32/Windows SDK, and Windows CNG (BCrypt, for SHA-256)
are the only dependencies; `std::regex` (standard library) backs the
obfuscation-decode detectors.

```powershell
cmake -S . -B build -G Ninja
cmake --build build --config Release
.\build\abyss_tests.exe
```

After building, `abyss.exe` looks for its rule pack relative to its own
location first, then `%ProgramData%\Abyss\rules`. After any change under
`rules/`, run `tools/generate_rules_manifest.ps1` (regenerates both the
manifest and the compiled trust anchor) and **rebuild** — a stale anchor
after a rules change makes the pack report as tampered until both are
redone together.

## Current, verified limitations

Real and tested in this build: static scanning (structural, behavioral,
obfuscation-aware), VS Code/extension preflight, the rule/trust engine,
the Git-propagation content tokenizer, output sanitization and secret
redaction, whole-PC discovery and persistence/network correlation,
transactional quarantine with rollback, safe clone/pull through a direct
`CreateProcessW` Git wrapper, Git timeline/graph/recovery, the
`AbyssProtection` Windows service and repository Git guards.

Genuine, current limitations (each produces an explicit `REVIEW`,
`INCOMPLETE`, or `UNRESOLVED` result — never a silent `ALLOW`):

- **No pre-installation telemetry.** Abyss has no historical process or
  network activity from before it was installed or before a given scan
  ran; `system-scan`'s network correlation only sees connections that are
  established *while the scan runs*.
- **Process, service, scheduled-task, Registry, and network findings stay
  review-controlled** unless corroborated by `Critical`+`Confirmed`
  repository file evidence — a process name or a launch string alone is
  never enough to auto-quarantine or auto-terminate anything, because a
  weak name match against legitimate software is a real failure mode
  Abyss deliberately refuses to act on.
- **Safe pull is fast-forward only.** A diverged branch is left for manual
  Git review rather than being merged or rebased automatically.
- **Existing Git hooks are preserved, not replaced.** `protect` reports a
  pre-existing `pre-commit`/`pre-push` hook instead of overwriting it, so
  a repository with custom hooks does not get Abyss's guard until that
  conflict is resolved manually.
- **Native Defender/Event Log incident correlation** (`abyss incident`) —
  not implemented; use Windows Security's own Protection History
  alongside `system-scan`'s findings.
- **No ETW-based runtime agent.** Abyss's coverage is point-in-time static
  and host-state analysis, not continuous kernel-level monitoring.
- **ZIP structural validation** is magic-bytes only (deliberately — a full
  central-directory parser is exactly the kind of variable-length,
  untrusted-length-driven code that tends to introduce its own
  vulnerabilities when hand-rolled under time pressure).
- **Code signing** — this build is unsigned; Authenticode signing requires
  a code-signing certificate the project does not have. Verify the binary
  by SHA-256 against the hash published with the release, and/or by
  reproducing the build from source with the commands above, rather than
  relying on Windows' own trust prompts.
- **Credential rotation stays under your control.** Abyss detects
  credential-shaped content and never collects, transmits, or revokes it
  itself — see [Manual credential recovery](#manual-credential-recovery-abyss-cannot-do-this-part-for-you).

## Contributing

Fixtures in `tests/`/`fixtures/` are inert `.sample` text/byte data only —
never a live executable payload, never something this project runs. Every
contribution must preserve that: no malicious fixture is ever executed,
`require()`d, `eval()`d, or passed to an interpreter, and no third-party
dependency (npm/Python/Rust/Go runtime, vcpkg/Conan package, third-party
JSON/YAML/security SDK, Catch2/GoogleTest) may be introduced — the
internal harness in `tests/test_harness.h` and the C++ standard library
are what this project uses throughout, deliberately.

If contributing a literal IOC signature, add it as data to
`rules/campaigns/*.rules` and re-run `tools/generate_rules_manifest.ps1`.
If contributing detection *logic*, it belongs in native C++
(`src/scanner`, `src/git`, `src/vscode`) — the split exists so campaign
rotation never requires an engine change, only a data change.

## Security

To report a vulnerability in Abyss itself (as opposed to a detection gap,
which is fine to file as a normal public issue with an inert `.sample`
reproduction), see [`SECURITY.md`](SECURITY.md). Do not attach live
malware samples to any report — reproduce the pattern as inert data
instead, per the fixture convention above.

## License

MIT — see [`LICENSE`](LICENSE).
