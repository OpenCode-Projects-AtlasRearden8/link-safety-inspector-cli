# Link Safety Inspector

**Pause before you click.** Paste a link (or a saved email text file) and get a
plain-English verdict about suspicious patterns — entirely on your own machine.

Part of the beginner-friendly tool collection from
[Asdale Dynamics, LLC](https://dylanasdale.github.io), the same team behind
*The Massive AI Manual* and the ai-scam-safety-guide and
passwords-and-two-step-guide. Explained like a friend would: step by step,
never condescending.

## Why it is different

- **No network fetches.** The tool never opens the link, never downloads the
  page behind it, and never asks anyone else — the page content is not scored
  anywhere. It only reads the *text* of the address you give it.
- **No accounts, no secrets, no personal data.** There is nothing to sign up
  for and nothing to leak.
- **It complements your judgment, it does not replace it.** The output is a
  set of *hesitations* — plain-English reasons to pause — plus a verdict from
  "Probably fine" to "Danger - do not click".

## What it checks

| Check | What it catches |
| --- | --- |
| Lookalike domains | `paypa1-secure.com`, `ww-wellsfargo.com`, buried brand names |
| Punycode tricks | hidden non-Latin characters that render like `apple.com` |
| Excess redirects | links that wrap other addresses in `?url=`, `?next=`, tracking layers |
| Shortener layers | `bit.ly`-style links, including a shortener hidden inside a redirect |
| http-only pages | unencrypted destinations that should be https |
| Credential-shape bait | pages dressed like logins, verifications, account alerts |
| Bare IP / odd port / odd ending | number-style addresses, weird ports, mass-abused TLDs like `.top` |
| Program downloads | links pointing straight at `.exe` and friends |
| @-sign illusion | `https://accounts.google.com@evil-site.net/...` |

## Install

Python 3.10 or newer. No third-party dependencies.

```bash
pip install .
```

That gives you a `link-safety-inspector` command. (Run `pip install -e .` if
you are editing the code.)

## How to use it

**One link:**

```bash
link-safety-inspector "https://paypa1-secure.com/verify/update-account"
```

```
Link:  https://paypa1-secure.com/verify/update-account
Verdict: Danger - do not click (score 7/10)
Hesitations:
  - The name "paypal" is buried inside "paypal-secure" — the real site would
    just be "paypal.com". Lookalike domain.
  - The page is dressed up like a login, verification, or account-alert page.
```

**A saved email text file** (save the message as plain text, `.txt` or `.eml`):

```bash
link-safety-inspector saved-email.txt
link-safety-inspector email saved-email.eml
```

**A batch file** (one link per line, `#` lines ignored):

```bash
link-safety-inspector batch links.txt
link-safety-inspector batch links.txt --format summary
link-safety-inspector batch links.txt --json
```

Want machine-readable output instead of prose? Add `--json` to any mode.

Running from source without installing:

```bash
python -m link_safety_inspector "https://bit.ly/9kK3x"
```

## What the verdicts mean

- **Probably fine** — no red flags from the offline checks.
- **Probably fine, stay sharp** — nothing major, just pause for a second.
- **Be careful** — real warning signs. Prefer typing the company's address
  yourself instead of clicking.
- **Danger - do not click** — strong scam signals. Report it as phishing and
  delete it.

## How to run the tests

```bash
pip install -e ".[dev]"
pytest
```

## Tips that the tool cannot do for you

- A lookalike check only knows the names it ships with. A brand-new scam
  domain can still slip past; your own pause is still the best detector.
- If an email claims to be your bank, open your bank's app or type its
  address yourself. Do not travel through the link.
- Put the guide duo beside this tool: ai-scam-safety-guide explains the scam
  patterns in plain English, and passwords-and-two-step-guide makes your
  accounts annoying enough that a stolen password is not a disaster.

## License

MIT — see [LICENSE](LICENSE). Built and maintained by
**Asdale Dynamics, LLC**. Copyright (c) 2026 Asdale Dynamics, LLC.
