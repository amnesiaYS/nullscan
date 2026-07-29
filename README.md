# nullscan

OSINT reconnaissance CLI: domain, email, username, IP, password leak checks.
Themed nullsec/dedsec. JSON and Markdown output for piping and sharing.

Two implementations ship in this repo:

- **`nullscan.ps1`** — PowerShell. Runs natively on Windows 10/11 with the
  built-in `powershell.exe` or PowerShell 7+. No Python, no install. This
  is the recommended path for Windows users.
- **`nullscan/`** (Python) — Linux/macOS users, or anyone who prefers Python.
  Install with `pip install -e .`.

## Install (Windows / PowerShell)

Download the two files and put them somewhere in your PATH (or run from the
folder where they live):

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/amnesiaYS/nullscan/main/nullscan.ps1 -OutFile nullscan.ps1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/amnesiaYS/nullscan/main/nullscan.cmd -OutFile nullscan.cmd
```

Then:

```
nullscan.cmd domain example.com
```

Or with PowerShell 7+ directly:

```powershell
pwsh -File .\nullscan.ps1 domain example.com
```

The `.cmd` wrapper sets `-ExecutionPolicy Bypass` so you do not need to
run `Set-ExecutionPolicy` first.

## Install (Linux / macOS / Python)

```bash
git clone https://github.com/amnesiaYS/nullscan
cd nullscan
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Requires Python 3.10+.

## Usage

```bash
# one target
nullscan domain example.com
nullscan email target@example.com
nullscan user somehandle
nullscan ip 1.1.1.1
nullscan leak password 'mypassword'

# multiple targets
nullscan domain example.com google.com github.com
nullscan ip 1.1.1.1 8.8.8.8 9.9.9.9

# machine-readable output
nullscan domain example.com --format json
nullscan domain example.com --format markdown
nullscan domain example.com --format json --output report.json

# control verbosity
nullscan domain example.com --no-banner --quiet
nullscan domain example.com --verbose --concurrency 20
```

The same flags work with the PowerShell script (replace `-` with `--`,
use `-Format json` etc.).

## Modules

### `domain <target>`

DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME), WHOIS via IANA referral,
subdomains from crt.sh Certificate Transparency logs, security
headers check on the HTTPS endpoint.

### `email <addr>`

RFC validation, MX records, disposable email blocklist, gravatar
hash, HIBP breach lookup (requires `HIBP_API_KEY`).

### `user <handle>`

Checks ~23 platforms: GitHub, Twitter/X, Reddit, Instagram,
YouTube, TikTok, Mastodon, HackerNews, Medium, StackOverflow,
Twitch, Pinterest, Telegram, VK, Steam, Spotify, SoundCloud,
DeviantArt, Flickr, GitLab, DockerHub, npm, PyPI.

### `ip <addr>`

Reverse DNS, ASN via Team Cymru DNS, geo via ip-api.com,
optional Shodan host intel (requires `SHODAN_API_KEY`).

### `leak password <pwd>`

HIBP password range API with k-anonymity. No API key required.
The full password hash never leaves the machine — only the first
five hex chars of the SHA-1 are sent.

## Configuration

API keys load from environment variables or
`~/.config/nullscan/config.toml` (Python) /
`%APPDATA%\nullscan\config.toml` (PowerShell):

| Variable             | Used by                  |
| -------------------- | ------------------------ |
| `HIBP_API_KEY`       | `email` breach lookup    |
| `SHODAN_API_KEY`     | `ip` host intel          |
| `VIRUSTOTAL_API_KEY` | (future modules)         |

Run `nullscan config` to see which keys are loaded.

## What this tool does not do

No exploits, no port scanning, no brute force, no payload
generation. Everything is passive or active-but-legal OSINT.
Respect the ToS of the services you query and GDPR for any
personal data you collect.

## License

MIT. See `LICENSE`.