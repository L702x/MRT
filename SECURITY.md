# Security Policy

## Supported Versions

Only the latest release of MRT is supported with security fixes. Older releases should not be relied upon.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

If you find a security issue in MRT (e.g. a bug that could let the tool be tricked into deleting/modifying the wrong files, a privilege escalation issue, a way to make it miss detections it should catch, or anything that could turn "malware remover" into "attack surface"), please report it responsibly:

- **Do not** open a public Issue for security vulnerabilities.
- Instead, report it privately via GitHub's [private vulnerability reporting](../../security/advisories/new) feature on this repo, or reach out directly to the maintainer (see contact links on the profile/README).
- Please include:
  - A description of the issue and its potential impact
  - Steps to reproduce (if applicable)
  - Your suggested severity, if you have one

## What to expect

- I'll acknowledge reports as soon as I can — this is a small, mostly solo-maintained project, so please be patient.
- If confirmed, a fix will be prioritized and a new release cut. Credit will be given in the release notes if you'd like it (let me know your preference when reporting).
- If a report turns out to be a non-issue or out of scope, I'll explain why.

## Scope notes

- MRT runs with Administrator privileges by design (to remove malware artifacts, registry keys, etc.). Reports about "the tool needs admin" are expected behavior, not a vulnerability — but reports about it **misusing** those privileges (e.g. touching files/keys it has no legitimate reason to touch) are very welcome.
- Since MRT ships as a compiled binary, please also flag if you notice anything in a release build that doesn't match the public source — that mismatch itself would be a serious issue to report immediately.
