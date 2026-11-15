[CmdletBinding()]
param(
    [ValidateSet('SessionRpc', 'SessionRpcBatch', 'SessionPair', 'SessionReadFiles')]
    [string]$Mode = 'SessionRpc',

    [ValidatePattern('^[A-Za-z0-9_.-]{1,96}$')]
    [string]$RequestId,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,180}$')]
    [string]$OutputName,

    [string]$PatchJsonPath,

    [switch]$AllowExistingPacket,

    [string]$SessionConfig,

    [string]$SessionRequest,

    [ValidatePattern('^[0-9a-f]{32}/[A-Za-z0-9_.-]{1,96}\.json$')]
    [string]$SessionOutputName,

    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$Fingerprint,

    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 60,

    [ValidateRange(30, 1800)]
    [int]$TransferTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sessionEntryTimer = [Diagnostics.Stopwatch]::StartNew()

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$canonicalRoot = $projectRoot
$canonicalTool = Join-Path $canonicalRoot 'local\windows_etx_packet.ps1'
$canonicalConfluenceRestore = Join-Path $canonicalRoot 'local\windows_confluence_restore.ps1'
$windowsPowerShell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$restoreOutputDirectory = $null

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        return $item.FullName
    }
    throw "Path is not a regular non-reparse file: $Path"
}

function Get-SessionSha256 {
    param([string]$Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hash.Dispose() }
}

function Assert-SessionRequestPath {
    param([string]$Path)
    $checked = Assert-RegularFile $Path
    $requestRoot = Join-Path $privateRoot 'requests'
    if (-not $checked.StartsWith($requestRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Session requests must stay inside .private/x11/session/requests'
    }
    $parent = [IO.Path]::GetDirectoryName($checked)
    while ($parent.Length -ge $privateRoot.Length) {
        $item = Get-Item -LiteralPath $parent -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Session request ancestors cannot be reparse points'
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $checked
}

function Invoke-SessionDelegate {
    param([hashtable]$Parameters)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $processArguments = [Environment]::GetCommandLineArgs()
    $compatible = $PSVersionTable.ContainsKey('PSEdition') -and
        $PSVersionTable.PSEdition -eq 'Desktop' -and
        $PSVersionTable.PSVersion.Major -eq 5 -and
        $processArguments -icontains '-NoProfile' -and
        $processArguments -icontains '-File' -and
        [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA' -and
        [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName.Equals(
            $windowsPowerShell, [StringComparison]::OrdinalIgnoreCase)
    if ($compatible) {
        $script:sessionDelegateMode = 'in_process'
        & $canonicalTool @Parameters
    }
    else {
        $script:sessionDelegateMode = 'separate_process'
        $delegateArguments = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $canonicalTool)
        foreach ($key in $Parameters.Keys) {
            $delegateArguments += @('-' + $key, [string]$Parameters[$key])
        }
        & $windowsPowerShell @delegateArguments
    }
    $script:sessionDelegateCode = $LASTEXITCODE
    $script:sessionDelegateSeconds = $timer.Elapsed.TotalSeconds
}

function Write-SessionJson {
    param([string]$Path, [object]$Value)
    $pending = $Path + '.pending-' + [guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($pending, ($Value | ConvertTo-Json -Depth 50 -Compress),
            [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) {
            $null = Assert-RegularFile $Path
            [IO.File]::Replace($pending, $Path, [NullString]::Value)
        }
        else { [IO.File]::Move($pending, $Path) }
    }
    finally { if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending } }
}

function Invoke-SessionBatch {
    # This is a bounded delegation loop. The canonical core owns all clipboard,
    # cryptography and protocol behavior, once per child request.
    $manifest = Get-Content -LiteralPath $SessionRequest -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($manifest.PSObject.Properties).Count -ne 2 -or $manifest.version -ne 1 -or
        @($manifest.requests).Count -lt 1 -or @($manifest.requests).Count -gt 5) {
        throw 'A session batch requires version 1 and one to five requests'
    }
    $group = $SessionOutputName.Split('/')[0]
    $ids = @{}; $profiles = @{}; $children = @()
    foreach ($item in $manifest.requests) {
        if (@($item.PSObject.Properties).Count -ne 4 -or $item.id -notmatch '^[0-9a-f]{32}$' -or
            $ids.ContainsKey($item.id) -or $item.request_sha256 -notmatch '^[0-9a-f]{64}$' -or
            $item.output_name -cne ($group + '/' + $item.id + '.json')) {
            throw 'Invalid or duplicate batch child'
        }
        $ids[$item.id] = $true
        $path = Assert-SessionRequestPath $item.request_file
        if ((Get-SessionSha256 $path) -cne $item.request_sha256) {
            throw 'Batch request hash mismatch'
        }
        $spec = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($spec.id -cne $item.id -or $spec.op -notin @(
            'workers', 'status', 'status_many', 'task_result', 'submit_simmer', 'submit_task')) {
            throw 'Batch operation is not a fixed Worker operation'
        }
        $mutating = $spec.op -in @('submit_simmer', 'submit_task')
        if ($mutating) {
            if ($spec.args.profile -notmatch '^work0[1-5]$' -or $profiles.ContainsKey($spec.args.profile)) {
                throw 'Batch submissions must use different Worker profiles'
            }
            $profiles[$spec.args.profile] = $true
        }
        $output = [IO.Path]::GetFullPath((Join-Path $sessionOutputRoot $item.output_name))
        if ($output -eq $sessionOutputPath) { throw 'Batch child cannot overwrite its aggregate' }
        if (Test-Path -LiteralPath $output) { $null = Assert-RegularFile $output }
        $children += [pscustomobject]@{id=$item.id; op=$spec.op; request=$path;
            request_sha256=$item.request_sha256; output=$output; output_name=$item.output_name; mutating=$mutating}
    }
    $manifestSha = Get-SessionSha256 $SessionRequest
    $progressPath = $SessionRequest + '.progress.json'
    $lockPath = $SessionRequest + '.lock'
    if (Test-Path -LiteralPath $lockPath) { $null = Assert-RegularFile $lockPath }
    $batchLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $delegateCalls = 0
    $delegateSeconds = 0.0
    try {
        if (Test-Path -LiteralPath $progressPath) {
            $null = Assert-RegularFile $progressPath
            $progress = Get-Content -LiteralPath $progressPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($progress.manifest_sha256 -cne $manifestSha -or @($progress.items).Count -ne $children.Count) {
                throw 'Batch progress does not match its immutable manifest'
            }
        }
        else {
            $progress = [pscustomobject]@{manifest_sha256=$manifestSha; items=@(
                foreach ($child in $children) {
                    [pscustomobject]@{id=$child.id; state='not_started'; receipt_sha256=$null;
                        exit_code=$null; error=$null; delegate_seconds=0.0}
                })}
            Write-SessionJson $progressPath $progress
        }
        for ($index=0; $index -lt $children.Count; $index++) {
            $child = $children[$index]; $state = $progress.items[$index]
            if ($state.id -cne $child.id -or $state.state -notin @('not_started','uncertain','complete')) {
                throw 'Invalid batch progress entry'
            }
            if ($child.mutating -and $state.state -eq 'complete') {
                $null = Assert-RegularFile $child.output
                if ((Get-SessionSha256 $child.output) -cne $state.receipt_sha256) {
                    throw 'Cached batch receipt hash mismatch'
                }
                continue
            }
            if ($child.mutating -and $state.state -eq 'uncertain') { continue }
            if ((Get-SessionSha256 $child.request) -cne $child.request_sha256) {
                throw 'Batch request changed before delegation'
            }
            # Persist uncertainty BEFORE dispatch. A lost outer process never
            # causes an automatic second submission of this child.
            $state.state = 'uncertain'; $state.error = $null
            Write-SessionJson $progressPath $progress
            try {
                $delegateCalls++
                Invoke-SessionDelegate @{Mode='SessionRpc'; SessionConfig=$SessionConfig;
                    SessionRequest=$child.request; OutputPath=$child.output}
                $state.exit_code = $script:sessionDelegateCode
                $state.delegate_seconds = $script:sessionDelegateSeconds
                $delegateSeconds += $script:sessionDelegateSeconds
                if ($state.exit_code -eq 0 -and (Test-Path -LiteralPath $child.output)) {
                    $null = Assert-RegularFile $child.output
                    $reply = Get-Content -LiteralPath $child.output -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($reply.ok -eq $true) {
                        $state.state = 'complete'
                        $state.receipt_sha256 = Get-SessionSha256 $child.output
                    }
                    else { $state.error = 'CHILD_REQUEST_FAILED' }
                }
                else { $state.error = 'CHILD_TRANSPORT_FAILED' }
            }
            catch { $state.error = 'CHILD_DELEGATION_FAILED' }
            Write-SessionJson $progressPath $progress
            if ($state.state -ne 'complete') { break }
        }
        $items = @(for ($index=0; $index -lt $children.Count; $index++) {
            $child=$children[$index]; $state=$progress.items[$index]
            [pscustomobject]@{id=$child.id; op=$child.op; state=$state.state;
                output_name=$child.output_name; receipt_sha256=$state.receipt_sha256;
                exit_code=$state.exit_code; error=$state.error; delegate_seconds=$state.delegate_seconds}
        })
        $ok = @($items | Where-Object state -ne 'complete').Count -eq 0
        Write-SessionJson $sessionOutputPath @{ok=$ok; manifest_sha256=$manifestSha; items=$items;
            timings=@{consumer_seconds=$sessionEntryTimer.Elapsed.TotalSeconds;
                delegate_calls=$delegateCalls; delegate_seconds=$delegateSeconds}}
        Write-Output (@{ok=$ok; response_file=$sessionOutputPath} | ConvertTo-Json -Compress)
        $script:sessionBatchCode = if ($ok) { 0 } else { 2 }
    }
    finally { $batchLock.Dispose() }
}

if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw 'Windows PowerShell is unavailable'
}
$canonicalTool = Assert-RegularFile $canonicalTool
if (-not $canonicalTool.StartsWith(
    $canonicalRoot + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw 'Canonical X11 tool resolved outside its project root'
}

$arguments = @(
    '-NoProfile',
    '-STA',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $canonicalTool
)

if ($Mode -in @('SessionRpc', 'SessionRpcBatch', 'SessionPair', 'SessionReadFiles')) {
    if ($RequestId -or $OutputName -or $PatchJsonPath -or -not $SessionOutputName) {
        throw 'Session mode requires a session output name and no legacy arguments'
    }
    $privateRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '.private\x11\session'))
    $expectedConfig = Join-Path $privateRoot 'client.json'
    $SessionConfig = Assert-RegularFile $SessionConfig
    if (-not $SessionConfig.Equals($expectedConfig, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Session configuration must be .private/x11/session/client.json'
    }
    $sessionOutputRoot = Join-Path $projectRoot '.work\x11\session'
    $sessionOutputPath = [IO.Path]::GetFullPath((Join-Path $sessionOutputRoot $SessionOutputName))
    if (-not $sessionOutputPath.StartsWith($sessionOutputRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Session output must stay inside .work/x11/session'
    }
    if (Test-Path -LiteralPath $sessionOutputPath) {
        $null = Assert-RegularFile $sessionOutputPath
    }
    foreach ($pathToCheck in @($SessionConfig, $sessionOutputPath)) {
        $parent = [IO.Path]::GetDirectoryName($pathToCheck)
        while ($parent -and $parent.Length -ge $projectRoot.Length) {
            if (Test-Path -LiteralPath $parent) {
                $parentItem = Get-Item -LiteralPath $parent -Force
                if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Reparse points are not supported in session paths'
                }
            }
            $parent = [IO.Path]::GetDirectoryName($parent)
        }
    }
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($sessionOutputPath)) -Force | Out-Null
    $sessionParameters = @{Mode=$Mode; SessionConfig=$SessionConfig; OutputPath=$sessionOutputPath}
    if ($Mode -eq 'SessionPair') {
        if (-not $Fingerprint -or $SessionRequest) { throw 'Pair requires only a fingerprint' }
        $sessionParameters.Fingerprint = $Fingerprint
    }
    else {
        if ($Fingerprint) { throw 'RPC does not accept a fingerprint' }
        $SessionRequest = Assert-SessionRequestPath $SessionRequest
        $sessionParameters.SessionRequest = $SessionRequest
    }
    if ($Mode -eq 'SessionRpcBatch') {
        Invoke-SessionBatch
        exit $script:sessionBatchCode
    }
    Invoke-SessionDelegate $sessionParameters
    Write-Output ('ETX_CONSUMER_TIMINGS=' + (@{mode=$script:sessionDelegateMode;
        consumer_seconds=$sessionEntryTimer.Elapsed.TotalSeconds;
        delegate_seconds=$script:sessionDelegateSeconds} | ConvertTo-Json -Compress))
    exit $script:sessionDelegateCode
}

throw 'This baseline exposes persistent session operations only'
