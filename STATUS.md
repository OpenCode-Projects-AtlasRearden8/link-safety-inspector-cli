# STATUS.md

## What was built

**Link Safety Inspector** — an offline command-line tool from Asdale
Dynamics, LLC that checks pasted links or saved email text files for
suspicious patterns and prints a plain-English verdict, plus hesitations
(the reasons behind the verdict). Designed to sit beside
ai-scam-safety-guide and passwords-and-two-step-guide.

- **No network fetch of page content.** The tool reads only the address text.
- **Nothing scored in the cloud.** Every check runs locally in Python.
- **No secrets, API keys, or personal data** anywhere in the code or repo.

### Components

- `src/link_safety_inspector/analyzer.py` — scoring engine: lookalike domains
  (Levenshtein + confusable homoglyph normalization + brand-name burial),
  punycode/`xn--` detection, mixed-script hosts, wrapped redirects
  (`?url=`, `?next=`, …) with recursive nested-destination scoring,
  shortener detection and shortener-inside-redirect chains, http-only pages,
  credential-shape bait (login/verify/account wording on unfamiliar domains),
  bare IPs, odd ports, abused TLDs, subdomain pileups, long URLs,
  @-sign userinfo tricks, and direct program downloads.
  Verdict bands: Probably fine / stay sharp (0–2), Be careful (3–4),
  Danger - do not click (5+).
- `src/link_safety_inspector/extract.py` — pulls links out of saved email
  text; `batch_urls()` reads one-link-per-line batch files (`#` comments ok).
- `src/link_safety_inspector/cli.py` — the console entry point; text or
  `--json` output; `--format summary` for batch runs; `email`/`batch`
  subcommands or bare-link auto-detection.
- `src/link_safety_inspector/domains.py` — data tables: trusted brand list,
  confusable character map, shortener list, abused TLDs, credential words,
  redirect parameter names.

## How to run it

```bash
pip install .            # or pip install -e ".[dev]" for tests too
link-safety-inspector "https://paypa1-secure.com/verify/update-account"
link-safety-inspector email saved-email.txt
link-safety-inspector batch links.txt --format summary
link-safety-inspector <any input> --json
python -m link_safety_inspector bit.ly/9kK3x        # from source
```

## Verification results

- `pytest`: **63 passed** (unit tests for every check, verdict bands,
  extractor, fixes against a 20+ URL legit-corpus to guard false positives,
  and CLI tests driving all three modes with real fixtures under
  `tests/fixtures/`).
- Manual end-to-end (checked by hand, careful to copy exactly):
  - `link-safety-inspector https://paypa1-secure.com/verify/update-account`
    → Danger 7/10 with lookalike + credential-bait hesitations. Correct.
  - `link-safety-inspector email tests/fixtures/scam_email_1.txt`
    → Danger 10/10 (lookalike + wrapped redirect + shortener chain + bait).
  - `link-safety-inspector email tests/fixtures/scam_email_2.txt` → line 1
    (bare IP + `.exe` + odd port + http) Danger 10/10; tinyurl line flagged
    as shortener. Correct.
  - `link-safety-inspector email tests/fixtures/legit_email.txt` → both
    github.com and calendar.google.com clean, 0/10. Correct, no false
    positives on trusted-brand login paths (`paypal.com/signin`,
    `myaccount.google.com/security` gives only a soft heads-up).
  - `link-safety-inspector batch tests/fixtures/batch_urls.txt --format summary`
    → 5 links: 2 Probably fine, 2 Danger, 1 stay sharp; worst link called out.
  - `link-safety-inspector <garbage text>` → "Danger - do not click" with a
    parse failure explanation, exit code 0 (a verdict, not a crash).
  - `--json` verified for single-link, email, and batch modes.

## Known gaps and planned improvements

- **Offline only, by design.** It cannot see a redirect's real landing page
  beyond what is written in the link text (wrapped `?url=` values are
  followed recursively, but server-side redirect chains are invisible).
- **Brand list is finite.** A trusted-brand name not in the shipped list
  (e.g. brand-new banks) cannot get a lookalike check yet; core domain-name
  checks still apply. Making the list extensible from a local file is a
  natural next step.
- **`t.co` and shortener logos**: shorteners are flagged as "can't see the
  destination" — appropriate, but users of t.co (official Twitter/X wrapper)
  will see a heads-up on otherwise normal links.
- **HTML emails**: if saved as raw `.html`, href-based extraction of `href=`
  attributes is not implemented; save as plain text or `.eml` instead.
- **No persistent history/log** — every run is stateless by design.
- Homoglyph coverage is a curated subset (most common Cyrillic/Greek/leetspeak
  confusables), not the full Unicode confusables tables.

## Housekeeping

- License: MIT, Copyright (c) 2026 Asdale Dynamics, LLC (see `LICENSE`).
- Credits: Asdale Dynamics, LLC (see `README.md`).
- Tests: `pytest` config lives in `pyproject.toml`; fixtures under
  `tests/fixtures/`.
