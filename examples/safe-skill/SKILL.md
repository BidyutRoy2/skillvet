---
name: tidy-notes
description: Summarise Markdown notes in a local folder into a weekly digest.
---

# Tidy Notes

A small, transparent skill. It only reads `.md` files inside the folder the
user points it at, and writes one digest file next to them.

## What it does

1. List the Markdown files in the user-provided folder.
2. Read each file (read-only).
3. Write `digest.md` in the same folder with a summary per file.

## What it never does

- No network access.
- No reading files outside the folder the user chose.
- No deleting or moving anything.
- No credentials are needed or used.

## Example

```bash
python -m skillvet scan examples/safe-skill   # this skill scores 100/100
```
