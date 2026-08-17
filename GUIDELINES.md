# Running Abyss — which directory, which command

This is a practical companion to `README.md`: exactly what to type,
depending on where your terminal actually is. If you'd rather not think
about any of this, double-click `abyss.exe` and use the menu — see
[Double-click interface](README.md#double-click-interface). Everything
below is for the command-line path.

## The two directories that matter

Every Abyss command potentially involves **two different folders**, and
they are independent of each other:

1. **Where `abyss.exe` itself lives** — call this the *tool folder*. It
   must contain `abyss.exe` next to its `rules/` directory (see
   [Rule trust](README.md#rule-trust)). This is the folder your terminal
   needs to either be *in*, or you need to give its full path.
2. **The project/repository you're pointing Abyss at** — the `<path>`
   argument most commands take. This can be anywhere on disk. Abyss never
   requires your terminal to be *inside* the project it's scanning —
   you always name it explicitly.

Mixing these up is the only real source of confusion: `.\abyss.exe` only
works when your terminal's current directory *is* the tool folder, because
`.\` means "right here." If your terminal is somewhere else, `.\abyss.exe`
will fail with "not recognized" — that's not a bug, it's Windows telling
you it can't find a program at `.\` from your current location.

## Three ways to invoke it, depending on where you are

**A. Your terminal is inside the tool folder.** Use `.\abyss.exe` and give
the project as a normal path (relative or absolute):

```powershell
cd "C:\Tools\Abyss"
.\abyss.exe scan "C:\dev\my-project"
.\abyss.exe scan-all "E:\Big Projects"
```

**B. Your terminal is inside the project you want to scan, and Abyss lives
elsewhere.** Use the tool's full path, and `.` for "this folder" as the
target:

```powershell
cd "C:\dev\my-project"
& "C:\Tools\Abyss\abyss.exe" scan .
& "C:\Tools\Abyss\abyss.exe" contain .
```

(`&` is PowerShell's call operator — required because the path contains a
space. In `cmd.exe` you don't need it: `"C:\Tools\Abyss\abyss.exe" scan .`)

**C. You added the tool folder to your own `PATH`.** Then `abyss` works
from *any* directory, no prefix needed:

```powershell
abyss scan "C:\dev\my-project"
```

Abyss never does this for you — see
[Getting started](README.md#getting-started-with-the-downloaded-release).
It's a one-time optional step in Windows Settings → Environment Variables,
entirely your choice.

## Your two scenarios, concretely

**"Scan everything under `E:\Big Projects` and clean what's confirmed
infected."** Your terminal's directory doesn't matter for the *target* —
`scan-all` takes a full path — but it does determine whether you type
`.\abyss.exe` or the tool's full path:

```powershell
# from inside the tool folder
.\abyss.exe scan-all "E:\Big Projects"
.\abyss.exe scan-all "E:\Big Projects" --yes

# from anywhere else
& "C:\Tools\Abyss\abyss.exe" scan-all "E:\Big Projects"
& "C:\Tools\Abyss\abyss.exe" scan-all "E:\Big Projects" --yes
```

**"Reject a colleague's infected repo on clone/pull."** Same pattern —
run `clone`/`pull` from wherever your terminal happens to be, prefixed
according to rule A/B/C above:

```powershell
# from inside the tool folder
.\abyss.exe clone https://github.com/owner/repo.git C:\dev\repo
.\abyss.exe pull C:\dev\repo

# from inside an existing repo you want to pull into
& "C:\Tools\Abyss\abyss.exe" pull .
```

## The one case where you don't invoke anything

Once `abyss protect <path>` has been run once (from an elevated terminal,
using either pattern above), Git itself calls Abyss automatically on every
`git commit` / `git push` inside that repository — the installed
`pre-commit`/`pre-push` hooks call `abyss.exe` by its absolute path, baked
in at the time you ran `protect`. Your terminal's current directory, and
whether Abyss is on `PATH`, do not matter for this case at all: it's Git
invoking the hook, not you invoking Abyss.

`abyss pull`/`abyss clone` are a different, *manual* boundary — they only
scan incoming content when you explicitly run them instead of plain
`git pull`/`git clone`. The service installed by `protect` is a third,
independent boundary: it re-scans registered project roots every five
seconds on its own, regardless of what any terminal is doing.

## Per-command quick reference

| Command | Needs a `<path>` argument | Needs Administrator | Needs Git for Windows installed |
| --- | --- | --- | --- |
| `check` | no | no | no |
| `scan` | yes | no | no |
| `scan-all` | yes (a parent folder) | no | no |
| `system-scan` | no (walks the whole PC) | no (fuller results if elevated) | no |
| `preflight` / `open` | yes | no | no |
| `contain` / `remediate` / `verify` | yes | no | no |
| `quarantine list` / `quarantine restore` | no / yes (a record ID) | no | no |
| `clone` | yes (a URL and a destination) | no | **yes** |
| `pull` | yes | no | **yes** |
| `timeline` / `graph` / `recover` | yes | no | **yes** |
| `protect` | yes | **yes** (installs a Windows service) | no |
| `unprotect` / `status` | yes / no | no | no |
| `rules list` / `rules verify` | no | no | no |
| `self-scan` | no (scans the tool's own install) | no | no |
| `version` | no | no | no |

"Needs Git for Windows installed" means Abyss shells out to a real
`git.exe` it finds on the machine (never bundled, never downloaded) — see
[Safe clone and pull](README.md#safe-clone-and-pull) for exactly how it's
located.

## Findings are written to a file, not scrolled past you

None of the commands above dump the full findings list to your terminal —
you get a few lines (scope, verdict, finding count) and a path to
`abyss-results\results.txt`, written inside whatever was scanned. See
[Where results are written](README.md#where-results-are-written) for
exactly where that file ends up for each command.

## Don't `scan-all` a folder that contains Abyss's own source

If Abyss's own project folder (or a clone/build of it) sits inside the
same parent you point `scan-all` or `system-scan` at, it will get scanned
like any other project — and it will produce a large wall of `CRITICAL`
`PolinRider` findings. This is expected, not a false alarm and not a real
infection: `rules/campaigns/polinrider.rules` and `fixtures/*.sample`
intentionally contain the literal malware marker strings as plain-text
signature/test data, and `tests/*.cpp` contains the same strings as
literal unit-test input. A scanner that didn't flag its own signature
file would be broken. Keep Abyss's own source tree in a separate location
from the projects you actually scan, or scan real projects individually,
so this expected noise doesn't bury a real finding elsewhere in a large
`scan-all` run.
