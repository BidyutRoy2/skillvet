# Contributing to skillvet

Thanks for helping make agent skills safer.

## Add a rule (best first contribution)

1. Open `skillvet/scanner.py` and add one entry to `RULES`:
   a unique `SV0xx` id, a severity, a regex, a one-line title, and a
   practical fix in the recommendation.
2. Add a test in `tests/test_scanner.py` with a real-world style example.
3. Run `python -m unittest discover -s tests -v`.

Rules must be specific: a rule that fires on normal, safe skills will be
rejected. Include the false-positive case you checked against.

## Development

```bash
git clone <this repo>
cd skillvet
python -m unittest discover -s tests -v
python -m skillvet scan examples/risky-skill
```

No dependencies are used on purpose — please keep it that way for the core
scanner.

## Reporting a bypass

Found a dangerous pattern skillvet misses? Open an issue with the minimal
example (redact any real credentials). See SECURITY.md for anything
sensitive.
