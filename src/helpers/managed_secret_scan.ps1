<#
  Safiye Managed Secret Scanner — reflection helper (short-lived CHILD PROCESS).

  Two tiers (the caller picks):
    SAFE (default)  : [Assembly]::ReflectionOnlyLoadFrom — reads compile-time
                      constant/literal values ONLY and executes ZERO target code.
                      Non-literal members are still surfaced by name/type with the
                      value withheld ("deep scan required"). Safe on any binary.
    DEEP (-Deep)    : [Assembly]::LoadFile + FieldInfo.GetValue — reads runtime
                      static values, which TRIGGERS the target's static
                      constructors (i.e. runs target code). Opt-in only. To bound
                      the executed surface, values are only read for "interesting"
                      types (a secret-like member/type name).

  Values are masked (length + SHA-256) unless -Reveal is passed (DEEP only).
  Output: one JSON object on stdout.
#>
param(
    [Parameter(Mandatory=$true)][string]$AssemblyPath,
    [switch]$Reveal,
    [switch]$Deep
)
$ErrorActionPreference = 'Stop'

# .NET regex IgnoreCase defaults to the CURRENT culture. On a Turkish (tr-TR)
# machine that breaks ASCII 'I'/'i' case folding, so [A-Za-z] and even a literal
# 'iv' silently fail to match names like "IV". Force CultureInvariant everywhere.
$script:RxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                 [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
function Test-Rx([string]$s, [string]$pat) {
    if ($null -eq $s) { return $false }
    return [regex]::IsMatch($s, $pat, $script:RxOpts)
}

function New-Masked([string]$s) {
    if ($null -eq $s) { return '' }
    $n = $s.Length
    if ($n -le 4) { return ('*' * $n) }
    if ($n -le 8) { return ($s.Substring(0,2) + ('*' * ($n-2))) }
    return ($s.Substring(0,4) + ('*' * [Math]::Min($n-6, 12)) + $s.Substring($n-2))
}
function Get-Sha256Hex([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLower() }
    finally { $sha.Dispose() }
}
# name -> (risk_label, severity)   (CultureInvariant via Test-Rx)
function Classify([string]$name) {
    if     (Test-Rx $name '(kripto|_iv\b|\biv\b|aes.?key|des.?key|crypt.?key|\bkey\b)')           { return @('embedded_crypto_key','HIGH') }
    elseif (Test-Rx $name '(private.?key|priv.?key|rsa.?key|pem)')                                 { return @('private_key','HIGH') }
    elseif (Test-Rx $name '(connection.?string|conn.?str|connstr|datasource|initial.?catalog)')   { return @('connection_string','HIGH') }
    elseif (Test-Rx $name '(client.?secret|app.?secret|\bsecret\b|passphrase)')                    { return @('hardcoded_secret','HIGH') }
    elseif (Test-Rx $name '(db.?sifre|sifre|password|passwd|\bpwd\b|parola)')                      { return @('hardcoded_password','HIGH') }
    elseif (Test-Rx $name '(api.?key|apikey|access.?key|bearer|\btoken\b|jwt)')                    { return @('hardcoded_token','HIGH') }
    elseif (Test-Rx $name '(salt|hmac|signing)')                                                   { return @('crypto_material','MEDIUM') }
    else                                                                                           { return @('possible_secret','MEDIUM') }
}
$namePattern = '(kripto|sifre|secret|passphrase|password|passwd|\bpwd\b|parola|token|jwt|db.?sifre|connection.?string|conn.?str|connstr|api.?key|apikey|access.?key|client.?secret|app.?secret|private.?key|priv.?key|\bkey\b|\biv\b|salt|hmac|bearer|crypt|aes|rsa|des|signing|credential)'

function Shannon([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return 0.0 }
    $freq = @{}; foreach ($c in $s.ToCharArray()) { $freq[$c] = ($freq[$c] + 1) }
    $H = 0.0; $len = $s.Length
    foreach ($k in $freq.Keys) { $p = $freq[$k] / $len; $H -= $p * [Math]::Log($p, 2) }
    return $H
}

$out = [ordered]@{
    assembly_path = $AssemblyPath
    assembly_name = ''
    type_count    = 0
    mode          = $(if ($Deep) {'deep'} else {'safe'})
    findings      = @()
    error         = $null
    reveal        = [bool]$Reveal
}

try {
    if (-not (Test-Path -LiteralPath $AssemblyPath)) { throw "File not found: $AssemblyPath" }
    $full = (Resolve-Path -LiteralPath $AssemblyPath).Path
    $out.assembly_path = $full

    if ($Deep) { $asm = [System.Reflection.Assembly]::LoadFile($full) }        # runs cctors on access
    else       { $asm = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($full) }  # zero execution
    $out.assembly_name = $asm.FullName

    $types = @()
    try { $types = $asm.GetTypes() }
    catch [System.Reflection.ReflectionTypeLoadException] { $types = $_.Exception.Types | Where-Object { $_ -ne $null } }
    $out.type_count = @($types).Count

    $flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::NonPublic
    $findings = New-Object System.Collections.ArrayList

    function Record($typeName, $memberName, $kind, $isPublic, $val, $valueAvailable, $shapeOnly) {
        $length = 0; $sha = ''; $masked = '(deep scan required)'; $vtype = 'string'
        if ($valueAvailable) {
            if ($val -is [byte[]]) { $vtype='byte[]'; $length=$val.Length; $sha=(Get-Sha256Hex $val); $masked=(New-Masked (([BitConverter]::ToString($val) -replace '-',''))) }
            elseif ($val -is [char[]]) { $vtype='char[]'; $s=(-join $val); $length=$s.Length; $sha=(Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($s))); $masked=(New-Masked $s) }
            else { $vtype='string'; $s=[string]$val; $length=$s.Length; $sha=(Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($s))); $masked=(New-Masked $s) }
            if ($length -eq 0) { return }
        }
        $cls = Classify $memberName
        $label = $cls[0]; $sev = $cls[1]
        if ($shapeOnly) { $label = 'high_entropy_value'; $sev = 'MEDIUM' }
        $item = [ordered]@{
            type=$typeName; member=$memberName; kind=$kind; is_public=[bool]$isPublic; is_static=$true
            value_type=$vtype; value_available=[bool]$valueAvailable; length=$length; sha256=$sha
            masked_value=$masked; risk_label=$label; severity=$sev
        }
        if ($Reveal -and $Deep -and $valueAvailable) {
            if ($val -is [byte[]]) { $item['value'] = ([BitConverter]::ToString($val) -replace '-','') }
            elseif ($val -is [char[]]) { $item['value'] = (-join $val) }
            else { $item['value'] = [string]$val }
        }
        [void]$findings.Add($item)
    }

    foreach ($t in $types) {
        $fields = @(); $props = @()
        try { $fields = $t.GetFields($flags) } catch {}
        try { $props  = $t.GetProperties($flags) } catch {}

        # A type is "interesting" if its name or any member name looks secret-like.
        # In DEEP mode we only read values (=run cctors) for interesting types.
        $typeInteresting = (Test-Rx $t.Name $namePattern)
        if (-not $typeInteresting) {
            foreach ($f in $fields) { if (Test-Rx $f.Name $namePattern) { $typeInteresting = $true; break } }
        }
        if (-not $typeInteresting) {
            foreach ($p in $props) { if (Test-Rx $p.Name $namePattern) { $typeInteresting = $true; break } }
        }

        foreach ($f in $fields) {
            $ft = $f.FieldType.FullName
            if ($ft -ne 'System.String' -and $ft -ne 'System.Byte[]' -and $ft -ne 'System.Char[]') { continue }
            $nameHit = (Test-Rx $f.Name $namePattern)
            if (-not $nameHit -and -not $typeInteresting) { continue }

            $val = $null; $avail = $false
            if ($Deep) {
                if ($typeInteresting) { try { $val = $f.GetValue($null); $avail = ($null -ne $val) } catch { $avail = $false } }
            } else {
                if ($f.IsLiteral) { try { $val = $f.GetRawConstantValue(); $avail = ($null -ne $val) } catch { $avail = $false } }
            }

            # value-shape / entropy fallback (DEEP only, needs a value): a boring-named
            # field whose value is a long high-entropy base64/hex blob.
            $shapeOnly = $false
            if (-not $nameHit) {
                if ($avail -and ($val -is [string]) -and $val.Length -ge 20 `
                    -and [regex]::IsMatch($val, '^[A-Za-z0-9+/=_-]+$', [System.Text.RegularExpressions.RegexOptions]::CultureInvariant) `
                    -and (Shannon $val) -ge 3.2) { $shapeOnly = $true }
                elseif ($avail -and ($val -is [byte[]]) -and ($val.Length -in @(16,24,32))) { $shapeOnly = $true }
                if (-not $shapeOnly) { continue }   # boring name + no strong shape -> skip
            }
            Record $t.FullName $f.Name 'field' $f.IsPublic $val $avail $shapeOnly
        }

        foreach ($p in $props) {
            if (-not $p.CanRead) { continue }
            if ($p.GetIndexParameters().Length -gt 0) { continue }
            $pt = $p.PropertyType.FullName
            if ($pt -ne 'System.String' -and $pt -ne 'System.Byte[]' -and $pt -ne 'System.Char[]') { continue }
            if (-not (Test-Rx $p.Name $namePattern)) { continue }
            $val = $null; $avail = $false
            if ($Deep) {                      # reading a property getter always runs code
                try { $val = $p.GetValue($null, $null); $avail = ($null -ne $val) } catch { $avail = $false }
            }
            $isPub = ($p.GetMethod -and $p.GetMethod.IsPublic)
            Record $t.FullName $p.Name 'property' $isPub $val $avail $false
        }
    }
    $out.findings = @($findings)
}
catch {
    $out.error = $_.Exception.Message
}

$out | ConvertTo-Json -Depth 5 -Compress
