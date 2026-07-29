#!/usr/bin/env pwsh
# nullscan — OSINT reconnaissance toolkit with a nullsec/dedsec flavor.
#
# Run with PowerShell 7+:
#   pwsh -File nullscan.ps1 domain example.com
#
# Or on Windows with the bundled launcher:
#   nullscan.cmd domain example.com
#
# Source: https://github.com/amnesiaYS/nullscan
# License: MIT
#
# No telemetry, no backdoor, no payload. The full source is plain text.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Targets = @(),

    [switch]$NoBanner,
    [switch]$NoColor,
    [ValidateSet('table', 'json', 'markdown')]
    [string]$Format = 'table',
    [string]$Output,
    [int]$Concurrency = 10,
    [switch]$Quiet,
    [switch]$Verbose,
    [ValidateSet('matrix', 'minimal', 'neon')]
    [string]$Theme = 'matrix',
    [switch]$Version,
    [switch]$ListThemes,
    [switch]$Path,
    [switch]$NoColorEnv
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

$Script:Version = '0.2.0'

# ---------------------------------------------------------------------------
# Theme: ANSI color codes
# ---------------------------------------------------------------------------

$Script:Ansi = @{
    Reset   = "`e[0m"
    Bold    = "`e[1m"
    Dim     = "`e[2m"
    Green   = "`e[32m"
    DarkGr  = "`e[38;5;28m"
    Cyan    = "`e[36m"
    Yellow  = "`e[33m"
    Red     = "`e[31m"
    Magenta = "`e[35m"
    Gray    = "`e[90m"
    White   = "`e[37m"
}

$Script:ThemeColors = @{
    matrix  = @{ primary = $Ansi.Green; accent = $Ansi.DarkGr; info = $Ansi.Cyan; warn = $Ansi.Yellow; bad = $Ansi.Red; muted = $Ansi.Gray; ok = $Ansi.Green }
    minimal = @{ primary = $Ansi.White; accent = $Ansi.White; info = $Ansi.Cyan; warn = $Ansi.Yellow; bad = $Ansi.Red; muted = $Ansi.Gray; ok = $Ansi.Green }
    neon    = @{ primary = $Ansi.Magenta; accent = $Ansi.Cyan; info = $Ansi.Cyan; warn = $Ansi.Yellow; bad = $Ansi.Magenta; muted = $Ansi.Gray; ok = $Ansi.Green }
}

# ---------------------------------------------------------------------------
# Output: stderr for status, stdout for data
# ---------------------------------------------------------------------------

function Write-Status {
    <#
    .SYNOPSIS
        Print a status line to stderr.
    #>
    param(
        [ValidateSet('ok', 'bad', 'warn', 'info', 'work')]
        [string]$Kind,
        [string]$Message
    )

    if ($Quiet) { return }

    $glyph = switch ($Kind) {
        'ok' { '[+]' }
        'bad' { '[-]' }
        'warn' { '[!]' }
        'info' { '[*]' }
        'work' { '[~]' }
    }

    $color = switch ($Kind) {
        'ok' { $Script:Ansi.Green }
        'bad' { $Script:Ansi.Red }
        'warn' { $Script:Ansi.Yellow }
        'info' { $Script:Ansi.Cyan }
        'work' { $Script:Ansi.Magenta }
    }

    $line = "$color$glyph$($Script:Ansi.Reset) $color$Message$($Script:Ansi.Reset)"
    [Console]::Error.WriteLine($line)
}

function Write-Info {
    <#
    .SYNOPSIS
        Print a labeled info line to stderr (key: value).
    #>
    param([string]$Label, [string]$Value)
    if (-not $Quiet) {
        [Console]::Error.WriteLine("$($Script:Ansi.DarkGr)$Label$($Script:Ansi.Reset): $($Script:Ansi.Green)$Value$($Script:Ansi.Reset)")
    }
}

function Write-Banner {
    <#
    .SYNOPSIS
        Print the nullscan banner plus system info.
    #>
    if ($NoBanner) { return }

    $banner = @"

 _   _ _ _   ____                 
| \ | | | | / ___|  ___  _ __   ___ _ __
|  \| | | | \___ \ / _ \| '_ \ / _ \ '__|
| |\  | | | | ___) | (_) | | | |  __/ |   
|_| \_|_|_| |____/ \___/|_| |_|\___|_|   

"@

    [Console]::Error.WriteLine("$($Script:Ansi.Green)$banner$($Script:Ansi.Reset)")
    [Console]::Error.WriteLine("$($Script:Ansi.DarkGr)// privacy is not a crime — recon in the silence$($Script:Ansi.Reset)")
    [Console]::Error.WriteLine("$($Script:Ansi.Gray)nullscan $Script:Version · nullsec collective · MIT$($Script:Ansi.Reset)")

    if (-not $Quiet) {
        $hostName = $env:COMPUTERNAME
        if (-not $hostName) { $hostName = [System.Net.Dns]::GetHostName() }
        $osName = if ($IsLinux) { 'linux' } elseif ($IsMacOS) { 'macos' } else { 'windows' }
        $psVer = $PSVersionTable.PSVersion.ToString()
        [Console]::Error.WriteLine("$($Script:Ansi.Gray)host: $hostName · $osName · powershell $psVer$($Script:Ansi.Reset)")
        [Console]::Error.WriteLine("$($Script:Ansi.Gray)theme: $Theme · format: $Format$($Script:Ansi.Reset)")
        [Console]::Error.WriteLine("$($Script:Ansi.Gray)$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')$($Script:Ansi.Reset)")
        [Console]::Error.WriteLine('')
    }
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

$Script:UserAgent = "nullscan/$Script:Version (+https://github.com/amnesiaYS/nullscan)"

function Invoke-HttpGet {
    <#
    .SYNOPSIS
        HTTP GET with timeout and a consistent user agent.
    .DESCRIPTION
        Returns the raw response body as a string, or $null on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 15,
        [hashtable]$Headers = @{}
    )
    try {
        $Headers['User-Agent'] = $Script:UserAgent
        return Invoke-WebRequest -Uri $Uri -Method Get -TimeoutSec $TimeoutSec -Headers $Headers -UseBasicParsing -ErrorAction Stop
    } catch {
        return $null
    }
}

function Invoke-HttpJson {
    <#
    .SYNOPSIS
        HTTP GET that parses JSON.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 15,
        [hashtable]$Headers = @{}
    )
    try {
        $Headers['User-Agent'] = $Script:UserAgent
        return Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec $TimeoutSec -Headers $Headers -ErrorAction Stop
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# DNS helpers (works on PowerShell 7+ with Resolve-DnsName; PowerShell 5.1
# on Windows 10+ has it too)
# ---------------------------------------------------------------------------

function Resolve-DnsRecords {
    <#
    .SYNOPSIS
        Run a DNS query and return answers as a flat list of strings.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type,
        [int]$TimeoutSec = 5
    )
    try {
        $results = Resolve-DnsName -Name $Name -Type $Type -ErrorAction SilentlyContinue
        if (-not $results) { return @() }

        # Resolve-DnsName returns objects that vary by record type.
        # Normalise to a list of strings.
        $out = @()
        foreach ($r in $results) {
            if ($r.IPAddress) { $out += $r.IPAddress }
            elseif ($r.NameExchange) { $out += "$($r.Preference) $($r.NameExchange)" }
            elseif ($r.NameHost) { $out += $r.NameHost.TrimEnd('.') }
            elseif ($r.PrimaryServer) { $out += $r.PrimaryServer }
            elseif ($r.Target) { $out += $r.Target.TrimEnd('.') }
            elseif ($r.Strings) { $out += ($r.Strings -join ' ') }
            elseif ($r.TxtData) { $out += $r.TxtData }
        }
        return $out | Where-Object { $_ }
    } catch {
        return @()
    }
}

function Resolve-Ptr {
    <#
    .SYNOPSIS
        Reverse DNS lookup (PTR) for an IPv4/IPv6 address.
    #>
    param([string]$Address)
    try {
        $results = Resolve-DnsName -Name $Address -Type PTR -ErrorAction SilentlyContinue
        if ($results) {
            return @($results | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue | ForEach-Object { $_.TrimEnd('.') })
        }
    } catch {}
    return @()
}

# ---------------------------------------------------------------------------
# WHOIS via raw TCP
# ---------------------------------------------------------------------------

function Invoke-Whois {
    <#
    .SYNOPSIS
        Perform a WHOIS lookup. Returns a hashtable with raw response and
        parsed fields.
    #>
    param([Parameter(Mandatory)][string]$Domain)

    $result = @{ server = 'whois.iana.org'; raw = ''; parsed = @{}; error = $null }

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect('whois.iana.org', 43)
        $client.ReceiveTimeout = 10000
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)
        $writer.WriteLine("$Domain`r`n")
        $writer.Flush()
        $ianaResp = $reader.ReadToEnd()
        $client.Close()
        $result.raw = $ianaResp

        # Find the referred WHOIS server.
        $referral = $null
        foreach ($line in $ianaResp -split "`n") {
            if ($line -match '^whois:\s*(\S+)') {
                $referral = $Matches[1]
                break
            }
        }

        if ($referral) {
            $result.server = $referral
            $client2 = New-Object System.Net.Sockets.TcpClient
            $client2.Connect($referral, 43)
            $client2.ReceiveTimeout = 10000
            $stream2 = $client2.GetStream()
            $writer2 = New-Object System.IO.StreamWriter($stream2)
            $reader2 = New-Object System.IO.StreamReader($stream2)
            $writer2.WriteLine("$Domain`r`n")
            $writer2.Flush()
            $result.raw = $reader2.ReadToEnd()
            $client2.Close()
        }
    } catch {
        $result.error = $_.Exception.Message
    }

    # Parse common fields.
    $patterns = @{
        registrar       = '(?im)^registrar:\s*(.+)'
        creation_date   = '(?im)^(?:creation date|created):\s*(.+)'
        expiration_date = '(?im)^(?:expir(?:y|ation) date|registry expiry date|expires):\s*(.+)'
        updated_date    = '(?im)^(?:updated date|last[- ]updated):\s*(.+)'
        status          = '(?im)^(?:domain status|status):\s*(.+)'
        nameservers     = '(?im)^(?:name server|nserver):\s*(.+)'
        emails          = '(?im)^(?:registrant|admin|tech) email:\s*(.+)'
        country         = '(?im)^country:\s*(.+)'
        org             = '(?im)^(?:org[- ]?name|organization|registrant organization):\s*(.+)'
    }
    foreach ($key in $patterns.Keys) {
        $matches_found = [regex]::Matches($result.raw, $patterns[$key])
        if ($matches_found.Count -gt 0) {
            $values = @($matches_found | ForEach-Object { $_.Groups[1].Value.Trim() } | Sort-Object -Unique)
            $result.parsed[$key] = if ($key -in @('nameservers', 'status', 'emails')) { $values } else { $values[0] }
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# ASN via Team Cymru DNS
# ---------------------------------------------------------------------------

function Get-AsnInfo {
    <#
    .SYNOPSIS
        Look up ASN info for an IPv4 address via Team Cymru DNS.
    #>
    param([Parameter(Mandatory)][string]$IpAddress)
    $reversed = ($IpAddress -split '\.')[-1..-4] -join '.'
    $result = @{ ip = $IpAddress }

    try {
        $txt = Resolve-DnsName -Name "$reversed.origin.asn.cymru.com" -Type TXT -ErrorAction SilentlyContinue
        if ($txt) {
            $line = ($txt.Strings -join '') -replace '"', ''
            $parts = $line -split '\|' | ForEach-Object { $_.Trim() }
            if ($parts.Count -ge 5) {
                $result.asn = $parts[0]
                $result.block = $parts[1]
                $result.country = $parts[2]
                $result.registry = $parts[3]
                $result.allocation_date = $parts[4]
                if ($parts.Count -ge 6) { $result.as_name = $parts[5] }
            }
        }
    } catch {}

    return $result
}

# ---------------------------------------------------------------------------
# crt.sh subdomain enumeration
# ---------------------------------------------------------------------------

function Get-CrtSubdomains {
    <#
    .SYNOPSIS
        Query crt.sh Certificate Transparency logs for subdomains.
    #>
    param([Parameter(Mandatory)][string]$Domain)
    $url = "https://crt.sh/?q=%25.$Domain&output=json"
    $resp = Invoke-HttpJson -Uri $url -TimeoutSec 30
    if (-not $resp) { return @() }
    $found = New-Object System.Collections.Generic.HashSet[string]
    foreach ($entry in $resp) {
        $names = $entry.name_value -split "`n"
        foreach ($n in $names) {
            $clean = $n.Trim().TrimStart('*.')
            if ($clean -and ($clean -eq $Domain -or $clean.EndsWith(".$Domain"))) {
                $null = $found.Add($clean.ToLower())
            }
        }
    }
    return @($found | Sort-Object)
}

# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------

$Script:SecurityHeaders = @(
    @{ name = 'Strict-Transport-Security'; label = 'HSTS' },
    @{ name = 'Content-Security-Policy';    label = 'CSP' },
    @{ name = 'X-Frame-Options';            label = 'clickjacking' },
    @{ name = 'X-Content-Type-Options';     label = 'MIME sniffing' },
    @{ name = 'Referrer-Policy';            label = 'referrer leak' },
    @{ name = 'Permissions-Policy';         label = 'feature policy' },
    @{ name = 'X-XSS-Protection';           label = 'legacy XSS filter' }
)

function Get-SecurityHeaders {
    <#
    .SYNOPSIS
        Fetch a URL and report which common security headers are present.
    #>
    param([string]$Url)
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        $present = @()
        $missing = @()
        foreach ($h in $Script:SecurityHeaders) {
            $value = $resp.Headers[$h.name]
            if ($value) { $present += [PSCustomObject]@{ header = $h.label; value = $value } }
            else { $missing += $h.label }
        }
        return [PSCustomObject]@{
            url     = $resp.BaseResponse.RequestMessage.RequestUri.ToString()
            status  = [int]$resp.StatusCode
            present = $present
            missing = $missing
        }
    } catch {
        return [PSCustomObject]@{ url = $Url; error = $_.Exception.Message; present = @(); missing = @() }
    }
}

# ---------------------------------------------------------------------------
# SHA-1 for HIBP k-anonymity
# ---------------------------------------------------------------------------

function Get-Sha1Hex {
    <#
    .SYNOPSIS
        SHA-1 hex digest of a UTF-8 string, uppercase.
    #>
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [System.Security.Cryptography.SHA1]::Create().ComputeHash($bytes)
    return (-join ($hash | ForEach-Object { $_.ToString('X2') }))
}

# ---------------------------------------------------------------------------
# Module: domain
# ---------------------------------------------------------------------------

function Get-DomainInfo {
    <#
    .SYNOPSIS
        Full domain recon: DNS, WHOIS, crt.sh subdomains, security headers.
    #>
    param([Parameter(Mandatory)][string]$Target)

    $Target = $Target.Trim().ToLower()
    if ($Target -match '^https?://') {
        $Target = ([System.Uri]$Target).Host
    }

    $result = [ordered]@{
        target     = $Target
        dns        = [ordered]@{}
        whois      = [ordered]@{ server = ''; parsed = [ordered]@{}; error = $null; raw = '' }
        subdomains = @()
        headers    = [ordered]@{}
    }

    $types = @('A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME')
    foreach ($t in $types) {
        $answers = Resolve-DnsRecords -Name $Target -Type $t
        if ($answers.Count -gt 0) { $result.dns[$t] = $answers }
    }

    $whoisData = Invoke-Whois -Domain $Target
    $result.whois = [ordered]@{
        server = $whoisData.server
        parsed = $whoisData.parsed
        error  = $whoisData.error
    }

    $subs = Get-CrtSubdomains -Domain $Target
    $result.subdomains = $subs

    if ($result.dns['A'] -or $result.dns['AAAA']) {
        $hdrs = Get-SecurityHeaders -Url "https://$Target/"
        $result.headers = $hdrs
    }

    return [PSCustomObject]$result
}

function Show-DomainResult {
    <#
    .SYNOPSIS
        Render a domain recon result as a rich table.
    #>
    param([Parameter(Mandatory)]$Result)

    Write-Status -Kind info -Message "target: $($Result.target)"

    if ($Result.dns.Keys.Count -gt 0) {
        [Console]::Error.WriteLine('')
        [Console]::Error]::WriteLine("$($Script:Ansi.Green)  DNS RECORDS$($Script:Ansi.Reset)")
        foreach ($type in @('A','AAAA','MX','NS','TXT','SOA','CNAME')) {
            if ($Result.dns[$type]) {
                $value = if ($type -eq 'TXT') { ($Result.dns[$type] -join ' | ') } else { ($Result.dns[$type] -join ', ') }
                [Console]::Error.WriteLine("$($Script:Ansi.DarkGr)  $type$($Script:Ansi.Reset) $($Script:Ansi.Green)$value$($Script:Ansi.Reset)")
            }
        }
    } else {
        Write-Status -Kind warn -Message "no DNS records found"
    }

    if ($Result.whois.error) {
        Write-Status -Kind bad -Message "WHOIS failed: $($Result.whois.error)"
    } elseif ($Result.whois.parsed.Keys.Count -gt 0) {
        [Console]::Error.WriteLine('')
        [Console]::Error]::WriteLine("$($Script:Ansi.Green)  WHOIS$($Script:Ansi.Reset)")
        foreach ($k in @('registrar','creation_date','expiration_date','status','country','org')) {
            if ($Result.whois.parsed[$k]) {
                Write-Info -Label "  $k" -Value $Result.whois.parsed[$k]
            }
        }
    }

    if ($Result.subdomains.Count -gt 0) {
        [Console]::Error.WriteLine('')
        [Console]::Error]::WriteLine("$($Script:Ansi.Green)  SUBDOMAINS via crt.sh ($($Result.subdomains.Count) total)$($Script:Ansi.Reset)")
        $display = $Result.subdomains | Select-Object -First 50
        foreach ($s in $display) {
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  $s$($Script:Ansi.Reset)")
        }
        if ($Result.subdomains.Count -gt 50) {
            Write-Status -Kind info -Message "$($Result.subdomains.Count - 50) more subdomains omitted"
        }
    } else {
        Write-Status -Kind info -Message "no subdomains found via crt.sh"
    }

    if ($Result.headers.error) {
        Write-Status -Kind warn -Message "headers: $($Result.headers.error)"
    } elseif ($Result.headers.present) {
        [Console]::Error]::WriteLine('')
        [Console]::Error]::WriteLine("$($Script:Ansi.Green)  SECURITY HEADERS$($Script:Ansi.Reset)")
        foreach ($h in $Result.headers.present) {
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  $($h.header)$($Script:Ansi.Reset): $($Script:Ansi.Green)$($h.value.Substring(0, [Math]::Min(80, $h.value.Length)))$($Script:Ansi.Reset)")
        }
        foreach ($m in $Result.headers.missing) {
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  $m$($Script:Ansi.Reset): $($Script:Ansi.Gray)— missing —$($Script:Ansi.Reset)")
        }
    }
}

# ---------------------------------------------------------------------------
# Module: email
# ---------------------------------------------------------------------------

$Script:DisposableDomains = @(
    '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
    'tempmail.com', 'temp-mail.org', 'yopmail.com',
    'maildrop.cc', 'dispostable.com', 'getnada.com',
    'sharklasers.com', 'throwawaymail.com', 'fakeinbox.com'
)

$Script:EmailRegex = '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'

$Script:TypoSuggestions = @{
    'gmial.com' = 'gmail.com'
    'gnail.com' = 'gmail.com'
    'yahooo.com' = 'yahoo.com'
    'hotmai.com' = 'hotmail.com'
    'outlok.com' = 'outlook.com'
}

function Get-EmailInfo {
    <#
    .SYNOPSIS
        Email recon: validation, MX, gravatar hash, disposable check, typo suggestion.
    #>
    param([Parameter(Mandatory)][string]$Address)

    $Address = $Address.Trim()
    $parts = $Address -split '@', 2
    $local = $parts[0]
    $domain = if ($parts.Length -gt 1) { $parts[1] } else { '' }

    $valid = $Address -match $Script:EmailRegex
    $isDisposable = $Script:DisposableDomains -contains $domain.ToLower()

    $result = [ordered]@{
        input     = $Address
        valid     = [bool]$valid
        local     = $local
        domain    = $domain
        disposable = [bool]$isDisposable
        mx        = @()
        gravatar  = $null
        suggestion = $Script:TypoSuggestions[$domain.ToLower()]
    }

    if ($valid -and -not $isDisposable) {
        $mxRecords = Resolve-DnsRecords -Name $domain -Type 'MX'
        $result.mx = $mxRecords
    }

    if ($valid) {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $hash = ($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Address.ToLower())) | ForEach-Object { $_.ToString('x2') }) -join ''
        $result.gravatar = [ordered]@{
            hash = $hash
            url = "https://www.gravatar.com/avatar/$hash`?d=404"
            profile = "https://www.gravatar.com/$hash.json"
        }
    }

    return [PSCustomObject]$result
}

function Show-EmailResult {
    param([Parameter(Mandatory)]$Result)
    if (-not $Result.valid) {
        Write-Status -Kind bad -Message "'$($Result.input)' is not a valid email address"
        return
    }
    Write-Status -Kind info -Message "target: $($Result.input)"
    Write-Info -Label 'format' -Value 'valid'
    Write-Info -Label 'disposable' -Value (if ($Result.disposable) { 'yes' } else { 'no' })
    Write-Info -Label 'mx_records' -Value (if ($Result.mx.Count -gt 0) { ($Result.mx -join ', ') } else { '(none)' })
    if ($Result.suggestion) {
        Write-Info -Label 'did you mean' -Value $Result.suggestion
    }
    if ($Result.gravatar) {
        [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  gravatar$($Script:Ansi.Reset): $($Script:Ansi.Green)$($Result.gravatar.hash.Substring(0,12))…$($Script:Ansi.Reset) $($Script:Ansi.Gray)($($Result.gravatar.url))$($Script:Ansi.Reset)")
    }
}

# ---------------------------------------------------------------------------
# Module: user
# ---------------------------------------------------------------------------

$Script:Platforms = @(
    [PSCustomObject]@{ name = 'GitHub';       url = 'https://github.com/{u}';         found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'GitLab';       url = 'https://gitlab.com/{u}';         found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Twitter/X';    url = 'https://twitter.com/{u}';        found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Reddit';       url = 'https://www.reddit.com/user/{u}'; found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Instagram';    url = 'https://www.instagram.com/{u}/';  found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'YouTube';      url = 'https://www.youtube.com/@{u}';   found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'TikTok';       url = 'https://www.tiktok.com/@{u}';    found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Mastodon';     url = 'https://mastodon.social/@{u}';   found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'HackerNews';   url = 'https://news.ycombinator.com/user?id={u}'; found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Medium';       url = 'https://medium.com/@{u}';        found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'StackOverflow'; url = 'https://stackoverflow.com/users/{u}'; found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Twitch';       url = 'https://www.twitch.tv/{u}';      found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Pinterest';    url = 'https://www.pinterest.com/{u}/';  found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Telegram';     url = 'https://t.me/{u}';               found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'VK';           url = 'https://vk.com/{u}';             found = 200; notFound = 404 }
    [PSCustomObject]@{ name = 'Steam';        url = 'https://steamcommunity.com/id/{u}'; found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'Spotify';      url = 'https://open.spotify.com/user/{u}'; found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'SoundCloud';   url = 'https://soundcloud.com/{u}';      found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'DeviantArt';   url = 'https://www.deviantart.com/{u}';  found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'Flickr';       url = 'https://www.flickr.com/people/{u}/'; found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'DockerHub';    url = 'https://hub.docker.com/u/{u}';    found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'npm';          url = 'https://www.npmjs.com/~{u}';      found = 200; notFound = 404 }
        [PSCustomObject]@{ name = 'PyPI';         url = 'https://pypi.org/user/{u}';       found = 200; notFound = 404 }
    )

    function Get-UserInfo {
        <#
        .SYNOPSIS
            Check ~23 platforms for one or more usernames.
        #>
        param([Parameter(Mandatory)][string]$Handle)

        $Handle = $Handle.Trim().TrimStart('@')
        $results = @()
        foreach ($p in $Script:Platforms) {
            $url = $p.url -replace '\{u\}', $Handle
            $status = 'unknown'
            $httpCode = 0
            try {
                $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
                $httpCode = [int]$resp.StatusCode
                if ($httpCode -eq $p.found) { $status = 'found' }
                elseif ($httpCode -eq $p.notFound) { $status = 'missing' }
                else { $status = "http_$httpCode" }
            } catch {
                $status = 'error'
            }
            $results += [PSCustomObject]@{
                platform = $p.name
                status   = $status
                url      = $url
                http     = $httpCode
            }
        }
        return [PSCustomObject]@{
            handle  = $Handle
            results = $results
            found   = @($results | Where-Object { $_.status -eq 'found' }).Count
        }
    }

    function Show-UserResult {
        param([Parameter(Mandatory)]$Result)
        Write-Status -Kind info -Message "handle: $($Result.handle)"
        $kind = if ($Result.found -gt 0) { 'ok' } else { 'info' }
        Write-Status -Kind $kind -Message "found on $($Result.found)/$($Result.results.Count) platforms"

        [Console]::Error]::WriteLine("$($Script:Ansi.Green)  USERNAME PRESENCE$($Script:Ansi.Reset)")
        foreach ($r in $Result.results) {
            $color = switch ($r.status) {
                'found' { $Script:Ansi.Green }
                'missing' { $Script:Ansi.Gray }
                'error' { $Script:Ansi.Red }
                default { $Script:Ansi.Yellow }
            }
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  $($r.platform.PadRight(14))$($Script:Ansi.Reset) $color$($r.status.PadRight(10))$($Script:Ansi.Reset) $($Script:Ansi.Gray)$($r.url)$($Script:Ansi.Reset)")
        }
    }

    # ---------------------------------------------------------------------------
    # Module: ip
    # ---------------------------------------------------------------------------

    function Get-IpInfo {
        <#
        .SYNOPSIS
            IP recon: reverse DNS, ASN, geo.
        #>
        param([Parameter(Mandatory)][string]$Address)

        $Address = $Address.Trim()
        $valid = [bool]($Address -match '^\d{1,3}(\.\d{1,3}){3}$') -or [bool]($Address -match '^[0-9a-fA-F:]+$')

        $result = [ordered]@{
            input      = $Address
            valid      = $valid
            reverse_dns = @()
            asn        = @{}
            geo        = @{}
        }

        if (-not $valid) {
            $result.error = 'not a valid IP address'
            return [PSCustomObject]$result
        }

        # Reverse DNS.
        try {
            $ptrHost = ([System.Net.Dns]::GetHostEntry($Address)).HostName
            if ($ptrHost -and $ptrHost -ne $Address) {
                $result.reverse_dns = @($ptrHost)
            }
        } catch {}

        # ASN (IPv4 only).
        if ($Address -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.asn = Get-AsnInfo -IpAddress $Address
        }

        # Geo via ip-api.com (free tier, no key).
        try {
            $geo = Invoke-HttpJson -Uri "http://ip-api.com/json/$Address?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query" -TimeoutSec 10
            if ($geo -and $geo.status -eq 'success') {
                $result.geo = $geo
            } elseif ($geo) {
                $result.geo = @{ error = $geo.message }
            }
        } catch {
            $result.geo = @{ error = $_.Exception.Message }
        }

        return [PSCustomObject]$result
    }

    function Show-IpResult {
        param([Parameter(Mandatory)]$Result)
        if (-not $Result.valid) {
            Write-Status -Kind bad -Message $Result.error
            return
        }
        Write-Status -Kind info -Message "target: $($Result.input)"
        if ($Result.reverse_dns.Count -gt 0) {
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  reverse DNS$($Script:Ansi.Reset): $($Script:Ansi.Green)$($Result.reverse_dns -join ', ')$($Script:Ansi.Reset)")
        } else {
            Write-Status -Kind info -Message 'no reverse DNS record'
        }
        if ($Result.asn.asn) {
            [Console]::Error]::WriteLine('')
            [Console]::Error]::WriteLine("$($Script:Ansi.Green)  ASN$($Script:Ansi.Reset)")
            foreach ($k in @('asn','block','country','registry','allocation_date','as_name')) {
                if ($Result.asn[$k]) {
                    Write-Info -Label "    $k" -Value $Result.asn[$k]
                }
            }
        }
        if ($Result.geo -and -not $Result.geo.error) {
            [Console]::Error]::WriteLine('')
            [Console]::Error]::WriteLine("$($Script:Ansi.Green)  GEO / ISP$($Script:Ansi.Reset)")
            foreach ($k in @('country','regionName','city','isp','org','as')) {
                if ($Result.geo.$k) {
                    Write-Info -Label "    $k" -Value $Result.geo.$k
                }
            }
            if ($Result.geo.lat -and $Result.geo.lon) {
                Write-Info -Label '    lat,lon' -Value "$($Result.geo.lat), $($Result.geo.lon)"
            }
        } elseif ($Result.geo -and $Result.geo.error) {
            Write-Status -Kind warn -Message "geo lookup failed: $($Result.geo.error)"
        }
    }

    # ---------------------------------------------------------------------------
    # Module: leak
    # ---------------------------------------------------------------------------

    function Test-PasswordLeaked {
        <#
        .SYNOPSIS
            Check whether a password has appeared in known breach corpora (HIBP
            k-anonymity). Returns a hashtable with the breach count.
        #>
        param([Parameter(Mandatory)][string]$Password)

        $sha1 = Get-Sha1Hex -Text $Password
        $prefix = $sha1.Substring(0, 5)
        $suffix = $sha1.Substring(5)

        $result = [ordered]@{
            password   = $null  # never store or display the password itself
            prefix     = $prefix
            hash_suffix = $suffix
            count      = 0
            error      = $null
        }

        try {
            $resp = Invoke-WebRequest -Uri "https://api.pwnedpasswords.com/range/$prefix" -Method Get -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            foreach ($line in ($resp.Content -split "`n")) {
                $parts = $line -split ':', 2
                if ($parts.Count -eq 2 -and $parts[0].Trim().ToUpper() -eq $suffix) {
                    $result.count = [int]$parts[1].Trim()
                    break
                }
            }
        } catch {
            $result.error = $_.Exception.Message
        }

        return [PSCustomObject]$result
    }

    function Show-LeakResult {
        param([Parameter(Mandatory)]$Result)
        if ($Result.error) {
            Write-Status -Kind bad -Message "HIBP lookup failed: $($Result.error)"
            return
        }
        if ($Result.count -gt 0) {
            [Console]::Error]::WriteLine("$($Script:Ansi.Red)[!]$($Script:Ansi.Reset) $($Script:Ansi.Red)pwned: seen $($Result.count.ToString('N0')) times in known breach corpora$($Script:Ansi.Reset)")
            [Console]::Error]::WriteLine("$($Script:Ansi.Yellow)  change this password immediately and never reuse it$($Script:Ansi.Reset)")
        } else {
            Write-Status -Kind ok -Message 'not found in known breach corpora (HIBP)'
        }
        [Console]::Error]::WriteLine("$($Script:Ansi.Gray)  hash prefix: $($Result.prefix) (k-anonymity — full hash never sent)$($Script:Ansi.Reset)")
    }

    # ---------------------------------------------------------------------------
    # Markdown renderer
    # ---------------------------------------------------------------------------

    function ConvertTo-Markdown {
        <#
        .SYNOPSIS
            Render a recon result object as a markdown report.
        #>
        param(
            [string]$Module,
            [string]$Target,
            [Parameter(Mandatory)]$Data
        )

        $lines = @(
            "# nullscan — $Module report",
            '',
            "- **target**: ``$Target``",
            "- **module**: ``$Module``",
            "- **generated**: $((Get-Date).ToUniversalTime().ToString('o'))",
            "- **tool**: nullscan $Script:Version",
            ''
        )

        $skipKeys = @('input','target','handle','valid','version','domain','local_part','raw','error','password','hash_suffix')

        function _renderValue($v) {
            if ($null -eq $v) { return '_empty_' }
            if ($v -is [bool]) { return $(if ($v) { 'yes' } else { 'no' }) }
            if ($v -is [array]) { return ($(if ($v.Count -gt 0) { ($v -join ', ') } else { '_empty_' })) }
            if ($v -is [hashtable] -or $v -is [System.Collections.Specialized.OrderedDictionary]) {
                return ($v | ConvertTo-Json -Compress -Depth 5)
            }
            return $v.ToString()
        }

        $props = $Data.PSObject.Properties
        foreach ($p in $props) {
            $key = $p.Name
            if ($skipKeys -contains $key) { continue }
            $value = $p.Value
            if ($null -eq $value -or $value -eq '' -or ($value -is [array] -and $value.Count -eq 0)) { continue }

            $title = ($key -replace '_', ' ') -replace '\b\w', { $_.Value.ToUpper() }

            if ($value -is [hashtable] -or $value -is [System.Collections.Specialized.OrderedDictionary]) {
                $lines += "## $title"
                $lines += ''
                foreach ($k in $value.Keys) {
                    $lines += "- **$($k -replace '_', ' ')**: $(_renderValue $value[$k])"
                }
                $lines += ''
            } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $arr = @($value)
                $lines += "## $title ($($arr.Count))"
                $lines += ''
                $cap = [Math]::Min(200, $arr.Count)
                for ($i = 0; $i -lt $cap; $i++) {
                    $item = $arr[$i]
                    if ($item -is [hashtable] -or $item -is [System.Collections.Specialized.OrderedDictionary] -or $item.PSObject) {
                        if ($item.PSObject) {
                            $rendered = ($item.PSObject.Properties | ForEach-Object { "$($_.Name): $(_renderValue $_.Value)" }) -join ', '
                        } else {
                            $rendered = ($item.Keys | ForEach-Object { "$($_): $(_renderValue $item[$_])" }) -join ', '
                        }
                        $lines += "- $rendered"
                    } else {
                        $lines += "- $(_renderValue $item)"
                    }
                }
                if ($arr.Count -gt 200) {
                    $lines += "- _… $($arr.Count - 200) more_"
                }
                $lines += ''
            } else {
                $lines += "- **$title**: $(_renderValue $value)"
            }
        }

        $lines += ''
        $lines += '---'
        $lines += '_Report generated by nullscan. Verify findings independently._'
        $lines += ''
        return ($lines -join "`n")
    }

    # ---------------------------------------------------------------------------
    # Multi-target orchestration
    # ---------------------------------------------------------------------------

    function Invoke-MultiScan {
        <#
        .SYNOPSIS
            Run a scan function over one or more targets and render results.
        #>
        param(
            [Parameter(Mandatory)][string]$ModuleName,
            [Parameter(Mandatory)][string[]]$Targets,
            [Parameter(Mandatory)][scriptblock]$ScanFn,
            [Parameter(Mandatory)][scriptblock]$RenderFn
        )

        if ($Targets.Count -eq 0) {
            Write-Status -Kind bad -Message 'no targets provided'
            return 2
        }

        Write-Status -Kind info -Message "module: $ModuleName"
        Write-Status -Kind work -Message "targets: $($Targets.Count)"

        $started = Get-Date
        $results = @()
        $failed = 0

        foreach ($t in $Targets) {
            try {
                $r = & $ScanFn $t
            } catch {
                Write-Status -Kind bad -Message "$ModuleName $t`: $($_.Exception.Message)"
                $results += [PSCustomObject]@{ target = $t; result = @{ error = $_.Exception.Message }; error = $_.Exception.Message }
                $failed++
                continue
            }

            if ($Format -eq 'table') {
                & $RenderFn $r
            }
            $results += [PSCustomObject]@{ target = $t; result = $r; error = $null }
        }

        $elapsed = (Get-Date) - $started

        if ($Format -in @('json', 'markdown')) {
            $payload = if ($Targets.Count -eq 1 -and $results.Count -eq 1 -and $results[0].error -eq $null) {
                $results[0].result
            } else {
                [PSCustomObject]@{
                    tool         = 'nullscan'
                    version      = $Script:Version
                    generated_at = (Get-Date).ToUniversalTime().ToString('o')
                    module       = $ModuleName
                    results      = $results
                }
            }

            if ($Format -eq 'json') {
                $text = $payload | ConvertTo-Json -Depth 10
            } else {
                $targetJoined = if ($Targets.Count -gt 1) { ($Targets -join ', ') } else { $Targets[0] }
                $text = ConvertTo-Markdown -Module $ModuleName -Target $targetJoined -Data $payload
            }

            if ($Output) {
                $text | Out-File -FilePath $Output -Encoding utf8 -NoNewline
                Write-Status -Kind ok -Message "wrote report to $Output"
            } else {
                [Console]::Out.WriteLine($text)
            }
        } elseif ($Output) {
            # table format with --output: serialize the collected results as JSON.
            $text = ($results | ConvertTo-Json -Depth 10)
            $text | Out-File -FilePath $Output -Encoding utf8 -NoNewline
            Write-Status -Kind ok -Message "wrote report to $Output"
        }

        $msg = "scan complete in $([Math]::Round($elapsed.TotalSeconds, 2))s"
        if ($failed -gt 0) { $msg += " ($failed failed)" }
        Write-Status -Kind (if ($failed -eq 0) { 'ok' } else { 'warn' }) -Message $msg

        if ($failed -eq $Targets.Count -and $Targets.Count -gt 0) { return 1 }
        return 0
    }

    # ---------------------------------------------------------------------------
    # Config helpers
    # ---------------------------------------------------------------------------

    function Get-ConfigPath {
        if ($env:NULLSCAN_CONFIG) { return $env:NULLSCAN_CONFIG }
        $xdg = $env:XDG_CONFIG_HOME
        if (-not $xdg) {
            if ($IsWindows) { $xdg = Join-Path $env:APPDATA 'nullscan' }
            else { $xdg = Join-Path $env:HOME '.config/nullscan' }
        } else {
            $xdg = Join-Path $xdg 'nullscan'
        }
        return (Join-Path $xdg 'config.toml')
    }

    function Show-Help {
        $help = @"
    nullscan $Script:Version — OSINT reconnaissance toolkit (nullsec/dedsec flavor)

    USAGE
        pwsh -File nullscan.ps1 <command> [options] [targets...]
        nullscan.cmd <command> [options] [targets...]

    COMMANDS
        domain <targets>     DNS, WHOIS, subdomains (crt.sh), security headers
        email  <addrs>       Format check, MX records, gravatar, breach lookup
        user   <handles>     Check ~23 platforms for one or more usernames
        ip     <addrs>       Reverse DNS, ASN, geo (ip-api.com)
        leak   <passwords>   HIBP password k-anonymity check
        config               Show loaded API keys and theme
        help                 This help

    OPTIONS
        --format table|json|markdown    Output format (default: table)
        --output FILE                   Write data to FILE instead of stdout
        --concurrency N                 Max concurrent network requests (default 10)
        --no-banner                     Skip the ASCII banner
        --no-color                      Disable ANSI colors
        --quiet                         Suppress non-essential output
        --verbose                       Show detailed progress
        --theme matrix|minimal|neon     Color theme
        --list-themes                   List available themes and exit
        --version                       Show version and exit
        --path                          Print config file path

    EXAMPLES
        pwsh -File nullscan.ps1 domain example.com
        pwsh -File nullscan.ps1 domain example.com google.com --format json
        pwsh -File nullscan.ps1 leak 'mypassword' --format json
        pwsh -File nullscan.ps1 ip 1.1.1.1 --output report.json --format json

    MORE INFO
        https://github.com/amnesiaYS/nullscan
    "@
        [Console]::Out.WriteLine($help)
    }

    function Show-Config {
        $cfgPath = Get-ConfigPath
        Write-Status -Kind info -Message "config file: $cfgPath ($((Test-Path $cfgPath) -and 'present' -or 'missing'))"

        $envKeys = @{
            'HIBP_API_KEY'       = 'hibp'
            'SHODAN_API_KEY'     = 'shodan'
            'VIRUSTOTAL_API_KEY' = 'virustotal'
        }
        foreach ($pair in $envKeys.GetEnumerator()) {
            if ($env:$($pair.Key)) {
                $val = $env:$($pair.Key)
                $masked = if ($val.Length -gt 8) { $val.Substring(0,4) + '…' + $val.Substring($val.Length-2) } else { '***' }
                [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  $($pair.Value)$($Script:Ansi.Reset) $($Script:Ansi.Green)$masked$($Script:Ansi.Reset) $($Script:Ansi.Gray)(env:$($pair.Key))$($Script:Ansi.Reset)")
            }
        }
        [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)  theme$($Script:Ansi.Reset): $($Script:Ansi.Green)$Theme$($Script:Ansi.Reset)")
    }

    # ---------------------------------------------------------------------------
    # Main dispatcher
    # ---------------------------------------------------------------------------

    if ($Version) {
        [Console]::Out.WriteLine("nullscan $Script:Version")
        exit 0
    }

    if ($ListThemes) {
        [Console]::Out.WriteLine('matrix  minimal  neon')
        exit 0
    }

    if ($Path) {
        [Console]::Out.WriteLine((Get-ConfigPath))
        exit 0
    }

    if (-not $Command -or $Command -eq 'help') {
        Show-Help
        exit 0
    }

    Write-Banner

    $exitCode = 0
    switch ($Command) {
        'domain' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan domain <target> [target...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'domain' -Targets $Targets -ScanFn { Get-DomainInfo $args[0] } -RenderFn { Show-DomainResult $args[0] }
        }
        'email' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan email <addr> [addr...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'email' -Targets $Targets -ScanFn { Get-EmailInfo $args[0] } -RenderFn { Show-EmailResult $args[0] }
        }
        'user' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan user <handle> [handle...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'user' -Targets $Targets -ScanFn { Get-UserInfo $args[0] } -RenderFn { Show-UserResult $args[0] }
        }
        'ip' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan ip <addr> [addr...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'ip' -Targets $Targets -ScanFn { Get-IpInfo $args[0] } -RenderFn { Show-IpResult $args[0] }
        }
        'leak' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan leak <password> [password...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'leak' -Targets $Targets -ScanFn { Test-PasswordLeaked $args[0] } -RenderFn { Show-LeakResult $args[0] }
        }
        'config' {
            Show-Config
        }
        default {
            Write-Status -Kind bad -Message "unknown command '$Command'. Try 'help'."
            $exitCode = 2
        }
    }

    exit $exitCode