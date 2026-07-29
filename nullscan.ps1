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
    [ValidateSet('table', 'json', 'markdown', 'csv', 'html')]
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
    [string]$Text,
    [ValidateSet('all','md5','sha1','sha256','sha512','sha3_256','sha3_512')]
    [string]$Algorithm = 'all',
    [int]$Port = 443
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

$Script:Version = '0.3.0'

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
    # Module: hash
    # ---------------------------------------------------------------------------

    $Script:HashAlgorithms = @('md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512')

    function Get-HashAlgorithms {
        return $Script:HashAlgorithms
    }

    function Get-FileHashInfo {
        <#
        .SYNOPSIS
            Hash a file with the given algorithms (or all of them).
        .DESCRIPTION
            Returns a hashtable with the size and a per-algorithm digest map.
        #>
        param(
            [Parameter(Mandatory)][string]$Path,
            [string[]]$Algorithms = $Script:HashAlgorithms
        )

        $result = @{ input = $Path; kind = 'file'; size_bytes = 0; algorithms = @{}; error = $null }

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $result.error = 'file not found or not a regular file'
            return $result
        }

        $file = Get-Item -LiteralPath $Path
        $result.size_bytes = $file.Length

        $hashers = @{}
        foreach ($alg in $Algorithms) {
            try {
                $hashers[$alg] = [System.Security.Cryptography.HashAlgorithm]::Create($alg)
            } catch {
                $result.error = "algorithm '$alg' not supported on this platform (try a different one)"
                return $result
            }
        }

        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $buffer = New-Object byte[] 65536
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                foreach ($alg in $Algorithms) {
                    $hashers[$alg].TransformBlock($buffer, 0, $read, $null, 0) | Out-Null
                }
            }
            foreach ($alg in $Algorithms) {
                $hashers[$alg].TransformFinalBlock($buffer, 0, 0) | Out-Null
                $bytes = $hashers[$alg].Hash
                $result.algorithms[$alg] = -join ($bytes | ForEach-Object { $_.ToString('x2') })
            }
        } finally {
            $stream.Close()
            foreach ($alg in $Algorithms) { $hashers[$alg].Dispose() }
        }

        return $result
    }

    function Get-StringHashInfo {
        <#
        .SYNOPSIS
            Hash a string with the given algorithms.
        #>
        param(
            [Parameter(Mandatory)][string]$Text,
            [string[]]$Algorithms = $Script:HashAlgorithms
        )

        $result = @{ input = $Text; kind = 'text'; size_bytes = $Text.Length; algorithms = @{}; error = $null }

        foreach ($alg in $Algorithms) {
            try {
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($alg)
                $bytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
                $result.algorithms[$alg] = -join ($bytes | ForEach-Object { $_.ToString('x2') })
                $hasher.Dispose()
            } catch {
                $result.error = "algorithm '$alg' not supported on this platform"
                return $result
            }
        }

        return $result
    }

    function Show-HashResult {
        param([Parameter(Mandatory)]$Result)
        if ($Result.error) {
            Write-Status -Kind bad -Message "$($Result.input): $($Result.error)"
            return
        }
        [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)$($Result.kind)$($Script:Ansi.Reset) $($Script:Ansi.Green)$($Result.input)$($Script:Ansi.Reset) $($Script:Ansi.Gray)($($Result.size_bytes) bytes)$($Script:Ansi.Reset)")
        foreach ($alg in $Script:HashAlgorithms) {
            if ($Result.algorithms[$alg]) {
                Write-Info -Label "  $($alg.ToUpper())" -Value $Result.algorithms[$alg]
            }
        }
    }

    function Invoke-HashScan {
        <#
        .SYNOPSIS
            Run hash module over one or more inputs (files or a single string).
        #>
        param(
            [string[]]$Files,
            [string]$Text,
            [string]$Algorithm = 'all'
        )

        $algs = if ($Algorithm -eq 'all') { $Script:HashAlgorithms } else { @($Algorithm) }

        if ($null -ne $Text -and $Text -ne '') {
            return Get-StringHashInfo -Text $Text -Algorithms $algs
        }

        $results = @()
        foreach ($f in $Files) {
            $results += Get-FileHashInfo -Path $f -Algorithms $algs
        }
        if ($results.Count -eq 1) { return $results[0] }
        return @{ count = $results.Count; results = $results }
    }

    # ---------------------------------------------------------------------------
    # Module: mac (OUI vendor lookup)
    # ---------------------------------------------------------------------------

    $Script:OuiDatabase = @{
        '001A2B' = 'Apple';        '3C0754' = 'Apple';        'F0F61C' = 'Apple';        '0011D8' = 'Apple'
        '001E52' = 'Apple';        '0016CB' = 'Apple';        'F40F24' = 'Apple';        '7C6DF8' = 'Apple'
        '40A6D9' = 'Apple';        '60C547' = 'Apple';        '78A3E4' = 'Apple';        'DC2B61' = 'Apple'
        'AC3F94' = 'Apple';        '98D6BB' = 'Apple';        'B8E856' = 'Apple';        'C8E0EB' = 'Apple'
        '9C207B' = 'Apple';        'A4B197' = 'Apple';        '0CA89C' = 'Apple';        '34C059' = 'Apple'
        '00000C' = 'Cisco';        '00104B' = 'Cisco';        '0011BB' = 'Cisco';        '001B2A' = 'Cisco'
        '001D45' = 'Cisco';        '001E13' = 'Cisco';        '001E7A' = 'Cisco';        '001F26' = 'Cisco'
        '002219' = 'Cisco';        '0023EB' = 'Cisco';        '0024F7' = 'Cisco';        '0025B4' = 'Cisco'
        '5475D0' = 'Cisco';        'B0827E' = 'Cisco';        'F87B7A' = 'Cisco'
        '0013E8' = 'Intel';        '0015C0' = 'Intel';        '0016E6' = 'Intel';        '0018DE' = 'Intel'
        '0019D1' = 'Intel';        '001B21' = 'Intel';        '001B77' = 'Intel';        '001CC0' = 'Intel'
        '001D72' = 'Intel';        '001E64' = 'Intel';        '001E65' = 'Intel';        '001E67' = 'Intel'
        '002314' = 'Intel';        '00247E' = 'Intel';        '0024D6' = 'Intel';        '8086F2' = 'Intel'
        '001247' = 'Samsung';      '001599' = 'Samsung';      '00166B' = 'Samsung';      '0017C9' = 'Samsung'
        '0018AF' = 'Samsung';      '001A8A' = 'Samsung';      '001B98' = 'Samsung';      '001D25' = 'Samsung'
        '001D6E' = 'Samsung';      '001E7D' = 'Samsung';      '0021D1' = 'Samsung';      '0023D7' = 'Samsung'
        '0025C3' = 'Samsung';      '08D40C' = 'Samsung';      '24F5AA' = 'Samsung';      '30CDB7' = 'Samsung'
        'B8BBE0' = 'Samsung';      'F0E7C3' = 'Samsung';      '5CA8E0' = 'Samsung';      'B0C4E7' = 'Samsung'
        '001A11' = 'Google';       '3C5AB4' = 'Google';       'F4F5D8' = 'Google';       'F8A9D0' = 'Google'
        '7085C2' = 'Google';       'A4E0E6' = 'Google'
        '001125' = 'Microsoft';    '0017F2' = 'Microsoft';    '0019D7' = 'Microsoft';    '001D09' = 'Microsoft'
        '001E2D' = 'Microsoft';    '002248' = 'Microsoft';    '0025AE' = 'Microsoft';    '28D244' = 'Microsoft'
        '0001E6' = 'HP';           '00023F' = 'HP';           '000A57' = 'HP';           '000E7F' = 'HP'
        '0010E3' = 'HP';           '001635' = 'HP';           '001A4B' = 'HP';           '001E0B' = 'HP'
        '00237D' = 'HP';           '002481' = 'HP';           '0025B3' = 'HP';           '28D2D2' = 'HP'
        '3C4A92' = 'HP';           '80CE62' = 'HP';           '9C8E99' = 'HP';           'B05B99' = 'HP'
        'B827EB' = 'Raspberry Pi Foundation'; 'DCA632' = 'Raspberry Pi Trading'
        '0018E7' = 'TP-Link';      'C0C9E3' = 'TP-Link';      '30B5C2' = 'TP-Link';      'DCAEF1' = 'TP-Link'
        'EC0861' = 'TP-Link';      'A842A1' = 'TP-Link'
        '0013D4' = 'ASUS';         '0015F2' = 'ASUS';         '001A92' = 'ASUS';         '001BFC' = 'ASUS'
        '001E8C' = 'ASUS';         '00248C' = 'ASUS';         'F02FA8' = 'ASUS';         'AC9B84' = 'ASUS'
        '00146C' = 'Netgear';      '00184B' = 'Netgear';      '001E2A' = 'Netgear';      '00224B' = 'Netgear'
        '0026F2' = 'Netgear';      '04A182' = 'Netgear';      '9CC9EB' = 'Netgear'
        '000C29' = 'VMware';       '001C14' = 'VMware';       '005056' = 'VMware'
        '000D3A' = 'D-Link';       '0011A5' = 'D-Link';       '0015E9' = 'D-Link';       '0016E4' = 'D-Link'
        '001CF0' = 'D-Link';       '001D7A' = 'D-Link';       '002191' = 'D-Link';       '1CAFF7' = 'D-Link'
        'B8A386' = 'D-Link';       'F07D68' = 'D-Link'
        '001E10' = 'Huawei';       '002568' = 'Huawei';       '004A6B' = 'Huawei';       '081196' = 'Huawei'
        '207B93' = 'Huawei';       '484C68' = 'Huawei';       '706F81' = 'Huawei';       'ACCF5C' = 'Huawei'
        'CC96A0' = 'Huawei';       'FCFFAA' = 'Huawei'
        '001E58' = 'Xiaomi';       '002273' = 'Xiaomi';       '2882E9' = 'Xiaomi';       '34CE69' = 'Xiaomi'
        '640980' = 'Xiaomi';       '78F29B' = 'Xiaomi';       'A0E1CF' = 'Xiaomi';       'C4150E' = 'Xiaomi'
        '001315' = 'Sony';         '001A80' = 'Sony';         '001D0D' = 'Sony';         '001FE4' = 'Sony'
        '0021B7' = 'Sony';         '5CB2C2' = 'Sony'
        '001656' = 'Nintendo';     '00191D' = 'Nintendo';     '0019FD' = 'Nintendo';     '001AE5' = 'Nintendo'
        '0021BD' = 'Nintendo';     '002403' = 'Nintendo';     '0025A0' = 'Nintendo';     'B8AEED' = 'Nintendo'
        '98B6E9' = 'Nintendo';     'CC9F7A' = 'Nintendo'
        '7C1E52' = 'Microsoft Xbox'; 'E45F01' = 'Microsoft Xbox'
        '001A11' = 'Espressif (ESP)'; '5CFF35' = 'Espressif (ESP)'; 'A020A6' = 'Espressif (ESP)'
        'BCFF4D' = 'Espressif (ESP)'; 'B4E62D' = 'Espressif (ESP)'
        '001DDF' = 'Sonoff';       'B4E62D' = 'Sonoff'
    }

    function Get-MacInfo {
        <#
        .SYNOPSIS
            Look up vendor for one or more MAC addresses.
        #>
        param([Parameter(Mandatory)][string[]]$Targets)

        $results = @()
        foreach ($raw in $Targets) {
            $clean = ($raw -replace '[^0-9a-fA-F]', '').ToUpper()
            if ($clean.Length -ne 12) {
                $results += [PSCustomObject]@{ input = $raw; error = 'not a valid MAC address'; mac = $null; oui = $null; vendor = $null; is_multicast = $false; is_private = $false }
                continue
            }
            $normalized = ($clean -split '(..)' -ne '' -join ':').TrimEnd(':')
            # Simpler: build colon-separated directly.
            $normalized = ($clean[0..1] -join '') + ':' + ($clean[2..3] -join '') + ':' + ($clean[4..5] -join '') + ':' + ($clean[6..7] -join '') + ':' + ($clean[8..9] -join '') + ':' + ($clean[10..11] -join '')
            $oui = $clean.Substring(0, 6)
            $vendor = if ($Script:OuiDatabase.ContainsKey($oui)) { $Script:OuiDatabase[$oui] } else { 'Unknown vendor' }
            $firstByte = [Convert]::ToInt32($clean.Substring(0, 2), 16)
            $results += [PSCustomObject]@{
                input       = $raw
                mac         = $normalized
                oui         = $oui
                vendor      = $vendor
                is_multicast = [bool]($firstByte -band 0x01)
                is_private  = ($oui -eq '020000')
                error       = $null
            }
        }
        $known = @($results | Where-Object { $_.vendor -ne 'Unknown vendor' -and -not $_.error }).Count
        return [PSCustomObject]@{ count = $results.Count; known = $known; results = $results }
    }

    function Show-MacResult {
        param([Parameter(Mandatory)]$Data)
        if (-not $Data.results) {
            Write-Status -Kind info -Message 'no MAC addresses provided'
            return
        }
        $kind = if ($Data.known -gt 0) { 'ok' } else { 'info' }
        Write-Status -Kind $kind -Message "$($Data.known)/$($Data.count) MAC addresses matched a known vendor"
        foreach ($r in $Data.results) {
            if ($r.error) {
                Write-Status -Kind bad -Message "$($r.input): $($r.error)"
                continue
            }
            $statusKind = if ($r.vendor -ne 'Unknown vendor') { 'ok' } else { 'warn' }
            $glyph = if ($statusKind -eq 'ok') { '[+]' } else { '[!]' }
            [Console]::Error]::WriteLine("$($Script:Ansi.Green)$glyph$($Script:Ansi.Reset) $($Script:Ansi.Green)$($r.mac)$($Script:Ansi.Reset)  $($Script:Ansi.DarkGr)$($r.vendor)$($Script:Ansi.Reset)")
            if ($r.is_multicast) { Write-Status -Kind warn -Message "$($r.mac) has the multicast bit set" }
            if ($r.is_private) { Write-Status -Kind info -Message "$($r.mac) is a locally-administered address" }
        }
    }

    function Get-MacInfoSingle {
        param([string]$Target)
        return Get-MacInfo -Targets @($Target)
    }

    # ---------------------------------------------------------------------------
    # Module: phone (validation + E.164 normalization)
    # ---------------------------------------------------------------------------

    $Script:PhoneCountries = @{
        '1'   = @{ name = 'US/Canada'; lengths = @(10); trunk = '1' }
        '7'   = @{ name = 'Russia/Kazakhstan'; lengths = @(10); trunk = '8' }
        '20'  = @{ name = 'Egypt'; lengths = @(10); trunk = '0' }
        '27'  = @{ name = 'South Africa'; lengths = @(9); trunk = '0' }
        '30'  = @{ name = 'Greece'; lengths = @(10); trunk = '0' }
        '31'  = @{ name = 'Netherlands'; lengths = @(9); trunk = '0' }
        '32'  = @{ name = 'Belgium'; lengths = @(9); trunk = '0' }
        '33'  = @{ name = 'France'; lengths = @(9); trunk = '0' }
        '34'  = @{ name = 'Spain'; lengths = @(9); trunk = '9' }
        '39'  = @{ name = 'Italy'; lengths = @(6,7,8,9,10,11); trunk = '0' }
        '40'  = @{ name = 'Romania'; lengths = @(9); trunk = '0' }
        '41'  = @{ name = 'Switzerland'; lengths = @(9); trunk = '0' }
        '43'  = @{ name = 'Austria'; lengths = @(10); trunk = '0' }
        '44'  = @{ name = 'United Kingdom'; lengths = @(10); trunk = '0' }
        '45'  = @{ name = 'Denmark'; lengths = @(8); trunk = '9' }
        '46'  = @{ name = 'Sweden'; lengths = @(9); trunk = '0' }
        '47'  = @{ name = 'Norway'; lengths = @(8); trunk = '9' }
        '48'  = @{ name = 'Poland'; lengths = @(9); trunk = '0' }
        '49'  = @{ name = 'Germany'; lengths = @(10,11); trunk = '0' }
        '52'  = @{ name = 'Mexico'; lengths = @(10,11); trunk = '0' }
        '54'  = @{ name = 'Argentina'; lengths = @(10); trunk = '0' }
        '55'  = @{ name = 'Brazil'; lengths = @(10,11); trunk = '0' }
        '61'  = @{ name = 'Australia'; lengths = @(9); trunk = '0' }
        '65'  = @{ name = 'Singapore'; lengths = @(8); trunk = '9' }
        '81'  = @{ name = 'Japan'; lengths = @(10); trunk = '0' }
        '82'  = @{ name = 'South Korea'; lengths = @(9,10); trunk = '0' }
        '86'  = @{ name = 'China'; lengths = @(11); trunk = '0' }
        '90'  = @{ name = 'Turkey'; lengths = @(10); trunk = '0' }
        '91'  = @{ name = 'India'; lengths = @(10); trunk = '0' }
        '92'  = @{ name = 'Pakistan'; lengths = @(10); trunk = '0' }
        '94'  = @{ name = 'Sri Lanka'; lengths = @(9); trunk = '0' }
        '211' = @{ name = 'South Sudan'; lengths = @(9); trunk = '0' }
        '212' = @{ name = 'Morocco'; lengths = @(9); trunk = '0' }
        '213' = @{ name = 'Algeria'; lengths = @(9); trunk = '0' }
        '216' = @{ name = 'Tunisia'; lengths = @(8); trunk = '0' }
        '218' = @{ name = 'Libya'; lengths = @(9); trunk = '0' }
        '220' = @{ name = 'Gambia'; lengths = @(7); trunk = '0' }
        '221' = @{ name = 'Senegal'; lengths = @(9); trunk = '0' }
        '234' = @{ name = 'Nigeria'; lengths = @(10); trunk = '0' }
        '250' = @{ name = 'Rwanda'; lengths = @(9); trunk = '0' }
        '251' = @{ name = 'Ethiopia'; lengths = @(9); trunk = '0' }
        '254' = @{ name = 'Kenya'; lengths = @(9); trunk = '0' }
        '255' = @{ name = 'Tanzania'; lengths = @(9); trunk = '0' }
        '256' = @{ name = 'Uganda'; lengths = @(9); trunk = '0' }
        '260' = @{ name = 'Zambia'; lengths = @(9); trunk = '0' }
        '263' = @{ name = 'Zimbabwe'; lengths = @(9); trunk = '0' }
        '351' = @{ name = 'Portugal'; lengths = @(9); trunk = '0' }
        '352' = @{ name = 'Luxembourg'; lengths = @(9); trunk = '0' }
        '353' = @{ name = 'Ireland'; lengths = @(9); trunk = '0' }
        '354' = @{ name = 'Iceland'; lengths = @(7); trunk = '0' }
        '355' = @{ name = 'Albania'; lengths = @(9); trunk = '0' }
        '356' = @{ name = 'Malta'; lengths = @(8); trunk = '0' }
        '357' = @{ name = 'Cyprus'; lengths = @(8); trunk = '0' }
        '358' = @{ name = 'Finland'; lengths = @(9); trunk = '0' }
        '359' = @{ name = 'Bulgaria'; lengths = @(9); trunk = '0' }
        '370' = @{ name = 'Lithuania'; lengths = @(8); trunk = '0' }
        '371' = @{ name = 'Latvia'; lengths = @(8); trunk = '0' }
        '372' = @{ name = 'Estonia'; lengths = @(8); trunk = '0' }
        '373' = @{ name = 'Moldova'; lengths = @(8); trunk = '0' }
        '375' = @{ name = 'Belarus'; lengths = @(9); trunk = '0' }
        '376' = @{ name = 'Andorra'; lengths = @(6); trunk = '0' }
        '377' = @{ name = 'Monaco'; lengths = @(8); trunk = '0' }
        '380' = @{ name = 'Ukraine'; lengths = @(9); trunk = '0' }
        '381' = @{ name = 'Serbia'; lengths = @(9); trunk = '0' }
        '385' = @{ name = 'Croatia'; lengths = @(9); trunk = '0' }
        '386' = @{ name = 'Slovenia'; lengths = @(8); trunk = '0' }
        '420' = @{ name = 'Czech Republic'; lengths = @(9); trunk = '0' }
        '421' = @{ name = 'Slovakia'; lengths = @(9); trunk = '0' }
        '852' = @{ name = 'Hong Kong'; lengths = @(8); trunk = '0' }
        '853' = @{ name = 'Macau'; lengths = @(8); trunk = '0' }
        '855' = @{ name = 'Cambodia'; lengths = @(9); trunk = '0' }
        '880' = @{ name = 'Bangladesh'; lengths = @(10); trunk = '0' }
        '886' = @{ name = 'Taiwan'; lengths = @(9); trunk = '0' }
        '960' = @{ name = 'Maldives'; lengths = @(7); trunk = '0' }
        '961' = @{ name = 'Lebanon'; lengths = @(8); trunk = '0' }
        '962' = @{ name = 'Jordan'; lengths = @(9); trunk = '0' }
        '963' = @{ name = 'Syria'; lengths = @(9); trunk = '0' }
        '964' = @{ name = 'Iraq'; lengths = @(10); trunk = '0' }
        '965' = @{ name = 'Kuwait'; lengths = @(8); trunk = '0' }
        '966' = @{ name = 'Saudi Arabia'; lengths = @(9); trunk = '0' }
        '967' = @{ name = 'Yemen'; lengths = @(9); trunk = '0' }
        '968' = @{ name = 'Oman'; lengths = @(8); trunk = '0' }
        '971' = @{ name = 'United Arab Emirates'; lengths = @(9); trunk = '0' }
        '972' = @{ name = 'Israel'; lengths = @(9); trunk = '0' }
        '973' = @{ name = 'Bahrain'; lengths = @(8); trunk = '0' }
        '974' = @{ name = 'Qatar'; lengths = @(8); trunk = '0' }
        '975' = @{ name = 'Bhutan'; lengths = @(8); trunk = '0' }
        '976' = @{ name = 'Mongolia'; lengths = @(8); trunk = '0' }
        '977' = @{ name = 'Nepal'; lengths = @(10); trunk = '0' }
        '994' = @{ name = 'Azerbaijan'; lengths = @(9); trunk = '8' }
        '995' = @{ name = 'Georgia'; lengths = @(9); trunk = '8' }
        '996' = @{ name = 'Kyrgyzstan'; lengths = @(9); trunk = '8' }
        '998' = @{ name = 'Uzbekistan'; lengths = @(9); trunk = '8' }
    }

    function Get-PhoneInfo {
        <#
        .SYNOPSIS
            Parse and validate one or more phone numbers.
        #>
        param([Parameter(Mandatory)][string[]]$Targets)

        $results = @()
        foreach ($raw in $Targets) {
            $s = $raw.Trim()
            $plus = ''
            if ($s.StartsWith('+')) { $plus = '+' }
            $digits = ($s -replace '\D', '')
            $e164 = $plus + $digits

            if ([string]::IsNullOrEmpty($digits)) {
                $results += [PSCustomObject]@{ input = $raw; valid = $false; error = 'no digits found' }
                continue
            }

            $code = $null
            $info = $null
            foreach ($len in 3, 2, 1) {
                $prefix = $digits.Substring(0, [Math]::Min($len, $digits.Length))
                if ($Script:PhoneCountries.ContainsKey($prefix)) {
                    $code = $prefix
                    $info = $Script:PhoneCountries[$prefix]
                    break
                }
            }

            if (-not $info) {
                $results += [PSCustomObject]@{ input = $raw; normalized = $e164; valid = $false; country_code = $null; country_name = $null; error = 'unknown country code (prefix with +XX)' }
                continue
            }

            $national = $digits.Substring($code.Length)
            if ($code -eq '39' -and $national.StartsWith($info.trunk)) {
                $national = $national.Substring(1)
            }

            $validLength = $info.lengths -contains $national.Length
            $results += [PSCustomObject]@{
                input            = $raw
                normalized       = $e164
                valid            = [bool]$validLength
                country_code     = $code
                country_name     = $info.name
                national_number  = $national
                national_length  = $national.Length
                expected_lengths = $info.lengths
                trunk_prefix     = $info.trunk
                error            = if ($validLength) { $null } else { "length $($national.Length) not in expected $($info.lengths -join ',')" }
            }
        }
        $valid = @($results | Where-Object { $_.valid }).Count
        return [PSCustomObject]@{ count = $results.Count; valid = $valid; results = $results }
    }

    function Show-PhoneResult {
        param([Parameter(Mandatory)]$Data)
        if (-not $Data.results) {
            Write-Status -Kind info -Message 'no phone numbers provided'
            return
        }
        $kind = if ($Data.valid -eq $Data.count) { 'ok' } else { 'warn' }
        Write-Status -Kind $kind -Message "$($Data.valid)/$($Data.count) phone numbers parsed"
        foreach ($r in $Data.results) {
            if ($r.error -and -not $r.country_code) {
                Write-Status -Kind bad -Message "$($r.input): $($r.error)"
                continue
            }
            $kind = if ($r.valid) { 'ok' } else { 'warn' }
            $glyph = if ($kind -eq 'ok') { '[+]' } else { '[!]' }
            [Console]::Error]::WriteLine("$($Script:Ansi.Green)$glyph$($Script:Ansi.Reset) $($Script:Ansi.Green)$($r.normalized)$($Script:Ansi.Reset)  $($Script:Ansi.DarkGr)$($r.country_name)$($Script:Ansi.Reset) $($Script:Ansi.Gray)($($r.country_code), national $($r.national_length) digits)$($Script:Ansi.Reset)")
            if (-not $r.valid) {
                Write-Status -Kind warn -Message "  expected lengths: $($r.expected_lengths -join ', ')"
            }
        }
    }

    function Get-PhoneInfoSingle {
        param([string]$Target)
        return Get-PhoneInfo -Targets @($Target)
    }

    # ---------------------------------------------------------------------------
    # Module: cidr (expand IPv4/v6 ranges)
    # ---------------------------------------------------------------------------

    $Script:CidrMaxDisplay = 200
    $Script:CidrMaxTotal = 1000000

    function Get-CidrInfo {
        <#
        .SYNOPSIS
            Expand one or more CIDR ranges into a list of IPs.
        #>
        param([Parameter(Mandatory)][string[]]$Targets)

        $results = @()
        foreach ($raw in $Targets) {
            try {
                $network = [System.Net.IPNetwork]::Parse($raw.Trim())
                $total = 0
                $hosts = @()
                foreach ($ip in $network.GetAddresses()) {
                    $total++
                    if ($total -le $Script:CidrMaxTotal) { $hosts += $ip.ToString() }
                }
                $truncated = $total -gt $Script:CidrMaxTotal
                $isPrivate = $network.IsPrivate()
                $isMulticast = $network.IsMulticast()
                $results += [PSCustomObject]@{
                    input            = $raw
                    valid            = $true
                    version          = if ($network.AddressFamily -eq 'InterNetwork') { 4 } else { 6 }
                    network_address  = $network.Address.ToString()
                    netmask          = $network.Netmask.ToString()
                    prefix_length    = $network.PrefixLength
                    is_private       = $isPrivate
                    is_multicast     = $isMulticast
                    total_addresses  = $total
                    usable_hosts     = $hosts.Count
                    truncated        = $truncated
                    hosts            = $hosts
                    error            = $null
                }
            } catch {
                $results += [PSCustomObject]@{ input = $raw; valid = $false; error = $_.Exception.Message }
            }
        }
        $valid = @($results | Where-Object { $_.valid }).Count
        return [PSCustomObject]@{ count = $results.Count; valid = $valid; results = $results }
    }

    function Show-CidrResult {
        param([Parameter(Mandatory)]$Data)
        if (-not $Data.results) {
            Write-Status -Kind info -Message 'no CIDR ranges provided'
            return
        }
        $kind = if ($Data.valid -eq $Data.count) { 'ok' } else { 'warn' }
        Write-Status -Kind $kind -Message "$($Data.valid)/$($Data.count) CIDR ranges parsed"
        foreach ($r in $Data.results) {
            if ($r.error) {
                Write-Status -Kind bad -Message "$($r.input): $($r.error)"
                continue
            }
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)$($r.input)$($Script:Ansi.Reset)  $($Script:Ansi.Green)$($r.total_addresses) addresses$($Script:Ansi.Reset) $($Script:Ansi.Gray)(IPv$($r.version), /$($r.prefix_length), netmask $($r.netmask))$($Script:Ansi.Reset)")
            if ($r.is_private) { Write-Status -Kind info -Message 'private range (RFC1918 / ULA)' }
            if ($r.is_multicast) { Write-Status -Kind info -Message 'multicast range' }
            if ($r.truncated) {
                Write-Status -Kind warn -Message "truncated to first $($Script:CidrMaxTotal) of $($r.total_addresses) addresses"
            }
            if ($r.hosts.Count -gt 0) {
                $display = $r.hosts | Select-Object -First $Script:CidrMaxDisplay
                [Console]::Error]::WriteLine("$($Script:Ansi.Green)  HOSTS ($($r.usable_hosts) total)$($Script:Ansi.Reset)")
                foreach ($h in $display) {
                    [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)    $h$($Script:Ansi.Reset)")
                }
                if ($r.hosts.Count -gt $Script:CidrMaxDisplay) {
                    Write-Status -Kind info -Message "$($r.hosts.Count - $Script:CidrMaxDisplay) more hosts omitted from display"
                }
            }
        }
    }

    function Get-CidrInfoSingle {
        param([string]$Target)
        return Get-CidrInfo -Targets @($Target)
    }

    # ---------------------------------------------------------------------------
    # Module: cert (TLS certificate inspection)
    # ---------------------------------------------------------------------------

    function Get-CertInfo {
        <#
        .SYNOPSIS
            Fetch and parse the TLS certificate from one or more hosts.
        #>
        param(
            [Parameter(Mandatory)][string[]]$Targets,
            [int]$DefaultPort = 443,
            [int]$TimeoutSec = 10
        )

        $results = @()
        foreach ($raw in $Targets) {
            $target = $raw.Trim()
            $port = $DefaultPort
            $host = $target
            if ($target.Contains(':') -and -not $target.StartsWith('[')) {
                $parts = $target.Split(':', 2)
                $host = $parts[0]
                $port = [int]$parts[1]
            }

            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $tcp.Connect($host, $port)
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {
                    param($s, $cert, $chain, $errors) { return $true }
                })
                $ssl.ReadTimeout = $TimeoutSec * 1000
                $ssl.WriteTimeout = $TimeoutSec * 1000
                $ssl.AuthenticateAsClient($host)
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
                $ssl.Close()
                $tcp.Close()

                $sanList = @()
                foreach ($ext in $cert.Extensions) {
                    if ($ext.Oid.FriendlyName -eq 'Subject Alternative Name') {
                        $raw = [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new($ext)
                        foreach ($entry in $raw.EnumerateDnsNames()) { $sanList += "DNS:$entry" }
                        foreach ($entry in $raw.EnumerateIPAddresses()) { $sanList += "IP:$entry" }
                    }
                }

                $expiresIn = ($cert.NotAfter - (Get-Date)).Days
                $expiresSoon = ($expiresIn -ge 0 -and $expiresIn -le 30)
                $expired = ($expiresIn -lt 0)

                $results += [PSCustomObject]@{
                    input              = $raw
                    host               = $host
                    port               = $port
                    subject            = $cert.Subject
                    issuer             = $cert.Issuer
                    serial             = $cert.SerialNumber
                    version            = $cert.Version
                    signature_algorithm = $cert.SignatureAlgorithm.FriendlyName
                    not_before         = $cert.NotBefore.ToString('o')
                    not_after          = $cert.NotAfter.ToString('o')
                    days_until_expiry  = $expiresIn
                    sans               = $sanList
                    expired            = $expired
                    expires_soon       = $expiresSoon
                    error              = $null
                }
            } catch {
                $results += [PSCustomObject]@{ input = $raw; host = $host; port = $port; error = $_.Exception.Message }
            }
        }
        $errors = @($results | Where-Object { $_.error }).Count
        return [PSCustomObject]@{ count = $results.Count; errors = $errors; results = $results }
    }

    function Show-CertResult {
        param([Parameter(Mandatory)]$Data)
        foreach ($r in $Data.results) {
            if ($r.error) {
                Write-Status -Kind bad -Message "$($r.input): $($r.error)"
                continue
            }
            [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)$($r.host)$($Script:Ansi.Reset)$($Script:Ansi.Gray):$($r.port)$($Script:Ansi.Reset)  $($Script:Ansi.Green)$($r.subject)$($Script:Ansi.Reset)")
            if ($r.expired) {
                Write-Status -Kind bad -Message "expired $(-($r.days_until_expiry)) days ago ($($r.not_after))"
            } elseif ($r.expires_soon) {
                Write-Status -Kind warn -Message "expires in $($r.days_until_expiry) days ($($r.not_after))"
            } else {
                Write-Status -Kind ok -Message "valid for $($r.days_until_expiry) more days (until $($r.not_after))"
            }
            [Console]::Error]::WriteLine("$($Script:Ansi.Gray)  issuer: $($r.issuer)$($Script:Ansi.Reset)")
            [Console]::Error]::WriteLine("$($Script:Ansi.Gray)  signature_algorithm: $($r.signature_algorithm) · version: $($r.version)$($Script:Ansi.Reset)")
            if ($r.sans -and $r.sans.Count -gt 0) {
                [Console]::Error]::WriteLine("$($Script:Ansi.Green)  SUBJECT ALTERNATIVE NAMES ($($r.sans.Count) total)$($Script:Ansi.Reset)")
                $display = $r.sans | Select-Object -First 30
                foreach ($s in $display) { [Console]::Error]::WriteLine("$($Script:Ansi.DarkGr)    $s$($Script:Ansi.Reset)") }
                if ($r.sans.Count -gt 30) { Write-Status -Kind info -Message "$($r.sans.Count - 30) more SANs omitted" }
            }
        }
    }

    function Get-CertInfoSingle {
        param([string]$Target)
        return Get-CertInfo -Targets @($Target)
    }

    # ---------------------------------------------------------------------------
    # CSV renderer
    # ---------------------------------------------------------------------------

    function ConvertTo-Csv {
        <#
        .SYNOPSIS
            Render a recon result object as CSV: one row per key/value pair.
        #>
        param([Parameter(Mandatory)]$Data)

        $sb = New-Object System.Text.StringBuilder
        $null = $sb.AppendLine('key,value')

        function _flatten($obj, $prefix) {
            $rows = @()
            if ($obj -is [System.Collections.IDictionary]) {
                foreach ($k in $obj.Keys) {
                    $rows += _flatten $obj[$k] $(if ($prefix) { "$prefix.$k" } else { "$k" })
                }
            } elseif ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
                $i = 0
                foreach ($v in $obj) {
                    $rows += _flatten $v $(if ($prefix) { "$prefix.$i" } else { "$i" })
                    $i++
                }
            } elseif ($null -eq $obj) {
                $rows += ,@{ key = $prefix; value = '' }
            } elseif ($obj -is [bool]) {
                $rows += ,@{ key = $prefix; value = $(if ($obj) { 'true' } else { 'false' }) }
            } else {
                $v = "$obj" -replace '"', '""'
                $rows += ,@{ key = $prefix; value = $v }
            }
            return ,$rows
        }

        $all = _flatten $Data ''
        foreach ($row in $all) {
            $kEsc = ($row.key -replace '"', '""')
            $vEsc = ($row.value -replace '"', '""')
            $null = $sb.AppendLine("`"$kEsc`",`"$vEsc`"")
        }
        return $sb.ToString()
    }

    # ---------------------------------------------------------------------------
    # HTML renderer (self-contained, dark/light, print-friendly)
    # ---------------------------------------------------------------------------

    $Script:HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nullscan report — __MODULE__</title>
<style>
  :root { color-scheme: light dark; --bg:#fafafa; --fg:#1a1a1a; --muted:#6e6e6e; --accent:#00aa41; --accent-fg:#fff; --panel:#f0f0f0; --border:#ddd; --code-bg:#f5f5f5; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0e0e0e; --fg:#e6e6e6; --muted:#888; --accent:#00ff41; --accent-fg:#0e0e0e; --panel:#1a1a1a; --border:#2a2a2a; --code-bg:#1f1f1f; } }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,sans-serif; background:var(--bg); color:var(--fg); max-width:900px; margin:2em auto; padding:0 1.5em; line-height:1.55; }
  h1 { color:var(--accent); margin-bottom:0.2em; }
  h2 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:0.3em; margin-top:2em; }
  .meta { color:var(--muted); font-size:0.92em; margin-bottom:2em; }
  table { border-collapse:collapse; width:100%; margin:1em 0; }
  th,td { text-align:left; padding:0.5em 0.75em; border-bottom:1px solid var(--border); }
  th { background:var(--accent); color:var(--accent-fg); font-weight:600; }
  tr:nth-child(even) td { background:var(--panel); }
  details { margin:0.5em 0; }
  summary { cursor:pointer; font-weight:600; padding:0.3em 0; color:var(--accent); }
  pre { background:var(--code-bg); padding:1em; border-radius:4px; overflow-x:auto; font-size:0.85em; border:1px solid var(--border); }
  code { font-family:"SF Mono",Menlo,Consolas,monospace; }
  .ok { color:#00aa41; } .bad { color:#cc0000; } .warn { color:#cc8800; }
  footer { margin-top:3em; padding-top:1em; border-top:1px solid var(--border); color:var(--muted); font-size:0.85em; }
  @media print { body { background:white; color:black; } }
</style>
</head>
<body>
<h1>nullscan report</h1>
<p class="meta"><strong>__MODULE__</strong> · target: <code>__TARGET__</code><br>generated __GENERATED__ · nullscan __VERSION__</p>
__BODY__
<footer>Generated by <a href="https://github.com/amnesiaYS/nullscan" style="color:var(--accent);">nullscan</a>. Verify findings independently.</footer>
</body>
</html>
'@

    function _htmlEscape($text) {
        if ($null -eq $text) { return '' }
        return ($text.ToString() -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    }

    function ConvertTo-HtmlReport {
        <#
        .SYNOPSIS
            Render a recon result as a self-contained HTML report.
        #>
        param(
            [string]$Module,
            [string]$Target,
            [Parameter(Mandatory)]$Data
        )

        $generated = (Get-Date).ToUniversalTime().ToString('o')

        $body = ''
        if ($Data -is [System.Collections.IDictionary]) {
            foreach ($k in $Data.Keys) {
                $v = $Data[$k]
                if ($null -eq $v -or $v -eq '' -or ($v -is [System.Collections.IEnumerable] -and $v.Count -eq 0)) { continue }
                $body += "<h2 id=""sec-$($k)"">$(_htmlEscape $k)</h2>`n"
                $body += _renderValueHtml $v
            }
        } else {
            $body += _renderValueHtml $Data
        }

        $json = $Data | ConvertTo-Json -Depth 10 -Compress
        $jsonEsc = _htmlEscape $json
        $body += "<details><summary>Raw JSON</summary><pre><code>$jsonEsc</code></pre></details>"

        $html = $Script:HtmlTemplate
        $html = $html -replace '__MODULE__', (_htmlEscape $Module)
        $html = $html -replace '__TARGET__', (_htmlEscape $Target)
        $html = $html -replace '__GENERATED__', (_htmlEscape $generated)
        $html = $html -replace '__VERSION__', (_htmlEscape $Script:Version)
        $html = $html -replace '__BODY__', $body
        return $html
    }

    function _renderValueHtml($v) {
        if ($null -eq $v) { return '<em>empty</em>' }
        if ($v -is [bool]) { return "<span class='$(if($v){'ok'}else{'bad'})'>$(if($v){'yes'}else{'no'})</span>" }
        if ($v -is [string]) { return _htmlEscape $v }
        if ($v -is [int] -or $v -is [long] -or $v -is [double]) { return "$v" }
        if ($v -is [System.Collections.IDictionary]) {
            $rows = ''
            foreach ($k in $v.Keys) {
                $val = $v[$k]
                if ($null -eq $val -or $val -eq '' -or ($val -is [System.Collections.IEnumerable] -and @($val).Count -eq 0)) { continue }
                $rows += "<tr><th>$(_htmlEscape $k)</th><td>$(_renderValueHtml $val)</td></tr>"
            }
            return "<table>$rows</table>"
        }
        if ($v -is [System.Collections.IEnumerable]) {
            $arr = @($v)
            if ($arr.Count -eq 0) { return '<em>empty</em>' }
            $items = ''
            foreach ($x in ($arr | Select-Object -First 100)) {
                $items += "<li>$(_htmlEscape ($x | Out-String).Trim())</li>"
            }
            if ($arr.Count -gt 100) { $items += "<li><em>… $($arr.Count - 100) more</em></li>" }
            return "<ul>$items</ul>"
        }
        return _htmlEscape ($v | Out-String)
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

        if ($Format -in @('json', 'markdown', 'csv', 'html')) {
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

            $targetJoined = if ($Targets.Count -gt 1) { ($Targets -join ', ') } else { $Targets[0] }

            switch ($Format) {
                'json'     { $text = $payload | ConvertTo-Json -Depth 10 }
                'markdown' { $text = ConvertTo-Markdown -Module $ModuleName -Target $targetJoined -Data $payload }
                'csv'      { $text = ConvertTo-Csv -Data $payload }
                'html'     { $text = ConvertTo-HtmlReport -Module $ModuleName -Target $targetJoined -Data $payload }
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
        hash   <files>       MD5/SHA1/SHA256/SHA512/SHA3 of files (or --text string)
        mac    <addrs>       IEEE OUI vendor lookup for MAC address(es)
        phone  <numbers>     Validate and normalize phone numbers (E.164)
        cidr   <ranges>      Expand CIDR ranges into lists of IPs
        cert   <hosts>       Inspect TLS certificate(s) for host[:port]
        config               Show loaded API keys and theme
        help                 This help

    OPTIONS
        --format table|json|markdown|csv|html    Output format (default: table)
        --output FILE                            Write data to FILE instead of stdout
        --concurrency N                          Max concurrent network requests (default 10)
        --no-banner                              Skip the ASCII banner
        --no-color                               Disable ANSI colors
        --quiet                                  Suppress non-essential output
        --verbose                                Show detailed progress
        --theme matrix|minimal|neon              Color theme
        --list-themes                            List available themes and exit
        --version                                Show version and exit
        --path                                   Print config file path

    HASH OPTIONS
        --text "string"                          Hash this string instead of a file
        --algorithm <name>                       md5, sha1, sha256, sha512, sha3_256, sha3_512, or 'all'

    CERT OPTIONS
        --port N                                 Default TLS port when not in target (default 443)

    EXAMPLES
        pwsh -File nullscan.ps1 domain example.com
        pwsh -File nullscan.ps1 domain example.com google.com --format json
        pwsh -File nullscan.ps1 leak 'mypassword' --format json
        pwsh -File nullscan.ps1 ip 1.1.1.1 --output report.json --format json
        pwsh -File nullscan.ps1 hash README.md --algorithm sha256
        pwsh -File nullscan.ps1 hash --text 'hello world'
        pwsh -File nullscan.ps1 mac 00:1A:2B:3C:4D:5E B8:27:EB:11:22:33
        pwsh -File nullscan.ps1 phone '+39 333 1234567'
        pwsh -File nullscan.ps1 cidr 192.168.1.0/24
        pwsh -File nullscan.ps1 cert github.com google.com --format json
        pwsh -File nullscan.ps1 domain example.com --format html --output report.html

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
        'hash' {
            if (-not $Text -and $Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan hash <file> [file...] | nullscan hash --text "..."'
                $exitCode = 2
                break
            }
            $hashResult = Invoke-HashScan -Files $Targets -Text $Text -Algorithm $Algorithm
            if ($Format -eq 'table') {
                Show-HashResult -Result $hashResult
            } else {
                $targetJoined = if ($Text) { $Text } elseif ($Targets.Count -gt 1) { ($Targets -join ', ') } else { $Targets[0] }
                switch ($Format) {
                    'json'     { $text = $hashResult | ConvertTo-Json -Depth 10 }
                    'markdown' { $text = ConvertTo-Markdown -Module 'hash' -Target $targetJoined -Data $hashResult }
                    'csv'      { $text = ConvertTo-Csv -Data $hashResult }
                    'html'     { $text = ConvertTo-HtmlReport -Module 'hash' -Target $targetJoined -Data $hashResult }
                }
                if ($Output) {
                    $text | Out-File -FilePath $Output -Encoding utf8 -NoNewline
                    Write-Status -Kind ok -Message "wrote report to $Output"
                } else {
                    [Console]::Out.WriteLine($text)
                }
            }
            $exitCode = 0
        }
        'mac' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan mac <addr> [addr...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'mac' -Targets $Targets -ScanFn { Get-MacInfoSingle $args[0] } -RenderFn { Show-MacResult $args[0] }
        }
        'phone' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan phone <number> [number...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'phone' -Targets $Targets -ScanFn { Get-PhoneInfoSingle $args[0] } -RenderFn { Show-PhoneResult $args[0] }
        }
        'cidr' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan cidr <range> [range...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'cidr' -Targets $Targets -ScanFn { Get-CidrInfoSingle $args[0] } -RenderFn { Show-CidrResult $args[0] }
        }
        'cert' {
            if ($Targets.Count -eq 0) {
                Write-Status -Kind bad -Message 'usage: nullscan cert <host>[:port] [host...]'
                $exitCode = 2
                break
            }
            $exitCode = Invoke-MultiScan -ModuleName 'cert' -Targets $Targets -ScanFn { Get-CertInfoSingle $args[0] } -RenderFn { Show-CertResult $args[0] }
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