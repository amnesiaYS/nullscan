# nullscan

CLI for OSINT reconnaissance: domain, email, username, IP, password leak checks.
Themed nullsec/dedsec. JSON output for piping.

## Install

```bash
git clone https://github.com/adam20p/nullscan
cd nullscan
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Requires Python 3.10+.

## Usage

```bash
nullscan domain example.com
nullscan email target@example.com
nullscan user somehandle
nullscan ip 1.1.1.1
nullscan leak password 'mypassword'

nullscan domain example.com --json   # machine-readable output
nullscan domain example.com --no-banner
nullscan config                      # show loaded API keys
```

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
`~/.config/nullscan/config.toml`:

| Variable           | Used by                  |
| ------------------ | ------------------------ |
| `HIBP_API_KEY`     | `email` breach lookup    |
| `SHODAN_API_KEY`   | `ip` host intel          |
| `VIRUSTOTAL_API_KEY` | (future modules)       |

Run `nullscan config` to see which keys are loaded and where the
config file lives.

## What this tool does not do

No exploits, no port scanning, no brute force, no payload
generation. Everything is passive or active-but-legal OSINT.
Respect the ToS of the services you query and GDPR for any
personal data you collect.

## License

MIT. See `LICENSE`.