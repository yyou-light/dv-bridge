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
    [int]$TransferTimeoutSeconds = 600,
    [ValidateRange(1, 1800)]
    [int]$QueueWaitTimeoutSeconds = 600
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
$script:queueRemainingSeconds = [double]$QueueWaitTimeoutSeconds
. (Join-Path $PSScriptRoot 'EtxTransportQueue.ps1')

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

function Invoke-SessionDelegateRaw {
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
            $delegateArguments += '-' + $key
            $delegateArguments += [string]$Parameters[$key]
        }
        & $windowsPowerShell @delegateArguments
    }
    $script:sessionDelegateCode = $LASTEXITCODE
    $script:sessionDelegateSeconds = $timer.Elapsed.TotalSeconds
}

function Write-EtxQueueError {
    param([string]$Code, [string]$StatePath)
    if ($Code -notmatch '^[A-Z0-9_]{1,80}$') { $Code = 'ETX_QUEUE_LOCAL_ERROR' }
    Write-Output ('ETX_QUEUE_ERROR=' + (@{error=$Code; phase='queue'; not_sent=$true;
        state_file=$StatePath} | ConvertTo-Json -Compress))
}

function Invoke-SessionDelegate {
    param([hashtable]$Parameters, [scriptblock]$BeforeDispatch, [scriptblock]$OnNotSent,
        [object]$DispatchContext)
    $lease = $null; $success = $false; $interrupted = $false; $serviceSeconds = 0.0
    $script:sessionDelegateCode = 1; $script:sessionDelegateNotSent = $true
    $script:sessionDelegateAttempts = 0; $script:sessionDelegateSeconds = 0.0
    $script:sessionDelegateMode = 'not_started'; $script:sessionQueueSeconds = 0.0
    $script:sessionQueueCheckSeconds = 1.0
    $statePath = $Parameters.OutputPath + '.queue.json'
    try {
        $kind = [string]$Parameters.Mode
        $requestSha = $null
        if ($Parameters.ContainsKey('SessionRequest')) {
            $requestSha = Get-SessionSha256 $Parameters.SessionRequest
            if ($Parameters.Mode -eq 'SessionRpc') {
                $spec = Get-Content -LiteralPath $Parameters.SessionRequest -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($spec.op -notmatch '^[a-z][a-z0-9_]{0,63}$') { throw 'INVALID_QUEUE_OPERATION' }
                $kind = 'rpc-' + $spec.op
            }
        }
        $configSha = Get-SessionSha256 $Parameters.SessionConfig
        $lease = Enter-EtxQueue $projectRoot $kind $statePath $script:queueRemainingSeconds
        while ($true) {
            if ((Get-SessionSha256 $Parameters.SessionConfig) -cne $configSha -or
                ($requestSha -and (Get-SessionSha256 $Parameters.SessionRequest) -cne $requestSha)) {
                throw 'SESSION_INPUT_CHANGED_WHILE_QUEUED'
            }
            if ($BeforeDispatch) { & $BeforeDispatch $DispatchContext }
            Set-EtxQueueState $lease 'dispatch'
            $script:sessionDelegateNotSent = $false
            $script:sessionDelegateAttempts++
            $receiptBefore = $null
            if (Test-Path -LiteralPath $Parameters.OutputPath) {
                $null = Assert-RegularFile $Parameters.OutputPath
                $itemBefore = Get-Item -LiteralPath $Parameters.OutputPath
                $receiptBefore = [string]$itemBefore.LastWriteTimeUtc.Ticks + ':' +
                    [string]$itemBefore.Length + ':' + (Get-SessionSha256 $Parameters.OutputPath)
            }
            Invoke-SessionDelegateRaw $Parameters
            $serviceSeconds = $script:sessionDelegateSeconds
            $reply = $null
            if (Test-Path -LiteralPath $Parameters.OutputPath) {
                $null = Assert-RegularFile $Parameters.OutputPath
                $itemAfter = Get-Item -LiteralPath $Parameters.OutputPath
                $receiptAfter = [string]$itemAfter.LastWriteTimeUtc.Ticks + ':' +
                    [string]$itemAfter.Length + ':' + (Get-SessionSha256 $Parameters.OutputPath)
                # A killed/failed delegate may leave a previous receipt intact.
                # Only a response updated by this attempt can prove not-sent.
                if ($receiptAfter -cne $receiptBefore) {
                    $reply = Get-Content -LiteralPath $Parameters.OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
                }
            }
            if (-not $reply -and $script:sessionDelegateCode -eq 0) { throw 'ETX_RESPONSE_NOT_UPDATED' }
            Update-EtxChannelHealth $lease $reply
            $provenNotSent = $reply -and $reply.PSObject.Properties['error'] -and
                $reply.error -eq 'CLIPBOARD_BUSY' -and $reply.PSObject.Properties['phase'] -and
                $reply.phase -eq 'packet_mutex'
            if ($script:sessionDelegateCode -ne 0 -and $provenNotSent) {
                # A pre-update caller may race our readiness probe. Only this
                # exact pre-send error can be retried, with the SAME input ID.
                $script:sessionDelegateNotSent = $true
                if ($OnNotSent) { & $OnNotSent $DispatchContext }
                $lease.NotSentRetries++
                $lease.WaitSeconds += $serviceSeconds
                Wait-EtxPacketIdle $lease
                continue
            }
            $success = $script:sessionDelegateCode -eq 0 -and $reply -and
                $reply.PSObject.Properties['ok'] -and $reply.ok -eq $true
            if ($reply -and $reply.PSObject.Properties['interruption_count']) {
                $interrupted = [int]$reply.interruption_count -gt 0
            }
            # read-files may contain several RPCs; the top-level interruption
            # count describes only its last one. Conservatively omit long RPCs.
            if ($reply -and $reply.PSObject.Properties['timings'] -and $reply.timings.PSObject.Properties['rpc']) {
                if (@($reply.timings.rpc | Where-Object seconds -ge 30).Count) { $interrupted=$true }
            }
            break
        }
    }
    catch {
        $script:sessionDelegateCode = 1
        if ($script:sessionDelegateNotSent) {
            if ($OnNotSent) { & $OnNotSent $DispatchContext }
            if ($lease) { Set-EtxQueueState $lease 'not_sent' $_.Exception.Message }
            Write-EtxQueueError $_.Exception.Message $statePath
        }
        else { Write-Error -ErrorRecord $_ -ErrorAction Continue }
    }
    finally {
        if ($lease) {
            $script:sessionQueueSeconds = $lease.WaitSeconds
            $script:sessionQueueCheckSeconds = $lease.CheckSeconds
            $script:queueRemainingSeconds = [Math]::Max(0, $script:queueRemainingSeconds-$lease.WaitSeconds)
            Exit-EtxQueue $lease $success $serviceSeconds $interrupted
        }
    }
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
    $batchWait = [Diagnostics.Stopwatch]::StartNew()
    $batchLock = $null
    while ($null -eq $batchLock) {
        try {
            $batchLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        }
        catch [IO.IOException] {
            if (($_.Exception.HResult -band 0xffff) -notin @(32,33)) { throw }
            if ($batchWait.Elapsed.TotalSeconds -ge $script:queueRemainingSeconds) {
                try { Write-EtxQueueJson ($sessionOutputPath+'.queue.json') @{phase='not_sent';
                    not_sent=$true; error='ETX_QUEUE_WAIT_TIMEOUT'; queue_wait_seconds=$batchWait.Elapsed.TotalSeconds} } catch { }
                Write-EtxQueueError 'ETX_QUEUE_WAIT_TIMEOUT' ($sessionOutputPath+'.queue.json')
                $script:sessionBatchCode = 1
                return
            }
            $folder = Join-Path $projectRoot '.work\x11\transport-queue'
            $profile = Get-EtxQueueProfile $folder ('rpc-' + $children[0].op)
            try { Write-EtxQueueJson ($sessionOutputPath+'.queue.json') @{phase='waiting_request';
                not_sent=$true; queue_wait_seconds=$batchWait.Elapsed.TotalSeconds; check_seconds=$profile.CheckSeconds} } catch { }
            Start-Sleep -Milliseconds ([int][Math]::Max(1,[Math]::Min($profile.CheckSeconds*1000,
                ($script:queueRemainingSeconds-$batchWait.Elapsed.TotalSeconds)*1000)))
        }
    }
    $script:queueRemainingSeconds = [Math]::Max(0,$script:queueRemainingSeconds-$batchWait.Elapsed.TotalSeconds)
    $delegateCalls = 0
    $delegateSeconds = 0.0
    $queueSeconds = $batchWait.Elapsed.TotalSeconds
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
            # Waiting is still not_started. Mark uncertainty only AFTER admission
            # and immediately BEFORE delegating; a killed queued caller was not sent.
            $state.state = 'not_started'; $state.error = $null
            Write-SessionJson $progressPath $progress
            try {
                $context = @{state=$state; progress=$progress; path=$progressPath}
                Invoke-SessionDelegate @{Mode='SessionRpc'; SessionConfig=$SessionConfig;
                    SessionRequest=$child.request; OutputPath=$child.output} -DispatchContext $context -BeforeDispatch {
                        param($value)
                        $value.state.state='uncertain'; $value.state.error=$null
                        Write-SessionJson $value.path $value.progress
                    } -OnNotSent {
                        param($value)
                        $value.state.state='not_started'
                        Write-SessionJson $value.path $value.progress
                    }
                $delegateCalls += $script:sessionDelegateAttempts
                $queueSeconds += $script:sessionQueueSeconds
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
                else { $state.error = if ($script:sessionDelegateNotSent) {'CHILD_NOT_SENT'} else {'CHILD_TRANSPORT_FAILED'} }
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
                delegate_calls=$delegateCalls; delegate_seconds=$delegateSeconds; queue_wait_seconds=$queueSeconds}}
        try { Write-EtxQueueJson ($sessionOutputPath+'.queue.json') @{phase=$(if ($ok) {'complete'} else {'finished'});
            not_sent=($delegateCalls -eq 0); queue_wait_seconds=$queueSeconds} } catch { }
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
        delegate_seconds=$script:sessionDelegateSeconds; queue_wait_seconds=$script:sessionQueueSeconds;
        queue_check_seconds=$script:sessionQueueCheckSeconds} | ConvertTo-Json -Compress))
    exit $script:sessionDelegateCode
}

throw 'This baseline exposes persistent session operations only'
