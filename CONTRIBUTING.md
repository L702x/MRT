# Contributing to MRT

Thanks for wanting to contribute! To keep MRT safe and maintainable, contributions are currently limited in scope. Please read this before opening a PR.

## What you can contribute

- **YARA rules only.** Right now the only accepted community contributions are new or improved YARA detection rules, placed under the `rules/` folder.

## What you cannot contribute

- **No direct code changes.** PRs touching `main.go`, `go.mod`, or any other Go source files will not be accepted from outside contributors. If you think you've found a bug or have a feature idea, please open an Issue describing it instead of submitting code — the maintainer will handle implementation.

## Submitting a YARA rule

1. Fork the repo and add your rule under `rules/`.
2. Make sure your rule is well-formed and doesn't conflict with existing rules (no duplicate rule names).
3. Open a PR with a short description of what the rule detects and why it's useful.

## Credit for your rule

You keep full credit for any YARA rule you contribute. To be credited:

- Add your name/handle/link **yourself** as part of the rule file — for example as a comment above the rule, or inside a `description` / `author` meta field.
- Credit **must not** be placed inside the actual rule logic (the `strings` or `condition` blocks) — it should live in a comment or a meta field only, so it doesn't affect how the rule matches.

Example:

```yara
// Contributed by: YourName (https://yoursite.example)
rule Example_Malware_Family
{
    meta:
        author = "YourName"
        description = "Detects XYZ dropper based on ABC strings"
    strings:
        $a = "somestring"
    condition:
        $a
}
```

PRs with rules missing proper attribution formatting, or that attempt to embed credit inside the detection logic itself, will be asked to fix formatting before merge.

## Review process

All PRs are reviewed manually before merge. Please be patient — YARA rules are checked for correctness and false-positive risk before acceptance.
