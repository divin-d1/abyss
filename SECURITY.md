# Security Policy

Abyss is a security tool that parses untrusted, potentially
attacker-controlled input by design (repository contents, VS Code
manifests, Git objects). Bugs in Abyss itself — a crash, an out-of-bounds
read, or a bypass that makes a malicious file score as clean — are taken
seriously.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security bug in Abyss
itself (as opposed to a false negative in a detection rule, which is fine
to file publicly — see below).

Instead, open a private security advisory on the repository ("Security" ->
"Report a vulnerability"), or contact the maintainers directly if that is
unavailable. Include:

- The Abyss version/commit.
- A minimal reproduction file or repository layout (inert — see
  "Handling malicious samples" below).
- What you expected vs. what happened.

## Detection gaps vs. security bugs

A **false negative** (Abyss fails to flag something malicious) is a
detection-quality issue — file it as a normal public issue with the
`detection-gap` label, ideally with an inert `.sample` fixture reproducing
the pattern, following the fixture-naming convention in `fixtures/`.

A **security bug in Abyss's own code** (crash on malformed input, a path
that could lead to executing untrusted content, a memory-safety issue) is
handled via the private process above.

## Handling malicious samples in reports

Do not attach live/executable malware samples to any report, public or
private. Abyss's own fixture policy applies to reports too: use inert
`.sample`-suffixed text/byte content that reproduces the pattern without
being executable, matching the convention documented in
`README.md` and used throughout `fixtures/`.

## Scope

In scope: `src/`, `rules/`, the CMake build, and the CLI's handling of
untrusted repository content. Out of scope: vulnerabilities in system Git,
VS Code, npm, or other tooling Abyss inspects but does not implement —
report those upstream.
