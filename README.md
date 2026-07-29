# nullscan

> // privacy is not a crime — recon in the silence

OSINT reconnaissance toolkit con estetica **nullsec/dedsec**. CLI Python, single-binary friendly, output colorato, JSON-ready.

Pensato per supporter del movimento anti-chatcontrol che vogliono fare reconnaissance passiva e attiva (solo OSINT) su domini, email, username, IP e leak — con un look coerente.

## Caratteristiche

- 🛰 **5 moduli di recon**: `domain`, `email`, `user`, `ip`, `leak`
- 🎨 Output tematico con banner ASCII e palette matrix
- 📊 Output sia human-readable (rich tables) sia JSON per piping
- ⚡ Async I/O via `httpx`, DNS via `dnspython`
- 🔌 API key opzionali (HIBP, Shodan, VirusTotal) caricate da env o config file
- 🪶 Zero telemetria, zero callback, zero payload nascosti — il codice è leggibile end-to-end

## Installazione

```bash
git clone <this-repo>
cd nullsex
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Oppure senza venv:

```bash
pip install --user -e .
```

Requisiti: Python ≥ 3.10.

## Uso rapido

```bash
# Banner + help
nullscan --help

# Recon dominio: DNS, WHOIS, subdomains via crt.sh, security headers
nullscan domain example.com

# Email: validazione, MX, gravatar, breach check
nullscan email target@example.com

# Username enumeration su ~20 piattaforme
nullscan user somehandle

# IP: geo, ASN, reverse DNS
nullscan ip 1.1.1.1

# Leak: controlla se una password è stata pwnata (HIBP k-anonymity)
nullscan leak password 'mypassword'

# Output JSON per piping
nullscan domain example.com --json | jq .

# Niente banner (per script)
nullscan domain example.com --no-banner
```

## Moduli

### `domain <target>`

- Record DNS: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`
- WHOIS via referral IANA → registrar server
- Subdomain enumeration via Certificate Transparency (crt.sh)
- Security headers check (HSTS, CSP, X-Frame-Options, …)

### `email <addr>`

- RFC 5322 validation
- MX record check
- Disposable email blocklist (oltre 100 domini)
- Gravatar lookup
- HIBP breach lookup (serve `HIBP_API_KEY`)

### `user <handle>`

- Check presenza su 20+ piattaforme: GitHub, Twitter/X, Reddit, Instagram, YouTube, TikTok, Mastodon, HackerNews, Medium, StackOverflow, Twitch, Pinterest, Telegram, VK, Steam, Spotify, SoundCloud, DeviantArt, Flickr, GitLab, DockerHub, npm, PyPI.

### `ip <addr>`

- Reverse DNS
- ASN via Team Cymru DNS (no key)
- GeoIP via ip-api.com (free tier, no key)
- Shodan host info (opzionale, `SHODAN_API_KEY`)

### `leak password <pwd>`

- HIBP Password Range API (k-anonymity, **no key richiesta**)
- Restituisce count di occorrenze nei breach noti

## Configurazione

Le API key si caricano, in ordine di priorità, da:

1. Variabili d'ambiente: `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`
2. File TOML: `~/.config/nullscan/config.toml`

Esempio config:

```toml
# ~/.config/nullscan/config.toml
[api]
hibp = "your-key-here"
shodan = "your-key-here"
virustotal = "your-key-here"
```

Comando helper:

```bash
nullscan config           # mostra config caricata
nullscan config --path    # mostra path del config file
```

## Uso responsabile

Questo tool fa **solo OSINT passivo e attivo lecito**. Niente exploit, niente port scan, niente brute force.

Quando lo usi:

- Rispetta `robots.txt` e i TOS dei servizi che contatti
- Non scansionare target per cui non hai autorizzazione
- I dati personali raccolti sono soggetti al GDPR — conservali in modo appropriato
- Il modulo `leak password` non manda la password in chiaro: usa SHA-1 + k-anonymity (primi 5 char), come da specifica HIBP

Il tool è fornito "as-is", senza garanzie. L'autore non è responsabile dell'uso che ne fanno gli utenti.

## Licenza

MIT — vedi `LICENSE`.