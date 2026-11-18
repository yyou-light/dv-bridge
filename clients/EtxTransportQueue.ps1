# Consumer-side scheduling only. This module never accesses the clipboard or ETX.

function Write-EtxQueueJson {
    param([string]$Path, [object]$Value)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Invalid queue metadata path'
        }
    }
    $pending = $Path + '.pending-' + [guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($pending, ($Value | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($pending, $Path, [NullString]::Value) }
        else { [IO.File]::Move($pending, $Path) }
    }
    finally { if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending } }
}

function Get-EtxQueueProfile {
    param([string]$Root, [string]$Kind)
    $samples = @()
    try {
        $path = Join-Path $Root ($Kind + '.json')
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force
            if (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $item.Length -le 8192) {
                $saved = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($saved.version -eq 1) {
                    $samples = @($saved.samples | Where-Object {
                        $_ -is [ValueType] -and [double]$_ -gt 0 -and [double]$_ -le 3600 -and
                        -not [double]::IsNaN([double]$_) -and -not [double]::IsInfinity([double]$_)
                    } | Select-Object -Last 20)
                }
            }
        }
    }
    catch { $samples = @() }
    $mean = 3.0
    if ($samples.Count) { $mean = [double](($samples | Measure-Object -Average).Average) }
    return [pscustomobject]@{Samples=$samples; MeanSeconds=$mean; CheckSeconds=[Math]::Max(0.5, [Math]::Min(2.0, $mean / 3.0))}
}

function Set-EtxQueueState {
    param([object]$Lease, [string]$Phase, [string]$ErrorCode = '')
    $Lease.Phase = $Phase
    try {
        Write-EtxQueueJson $Lease.StatePath @{version=1; pid=$PID; kind=$Lease.Kind;
            phase=$Phase; not_sent=($Phase -in @('waiting_queue','waiting_active_transfer','ready','not_sent'));
            error=$ErrorCode; retry_after_seconds=$Lease.RetryAfterSeconds; queue_wait_seconds=[Math]::Round($Lease.WaitSeconds,6);
            elapsed_seconds=[Math]::Round($Lease.Watch.Elapsed.TotalSeconds,6);
            check_seconds=$Lease.CheckSeconds; mean_service_seconds=$Lease.MeanSeconds;
            checks=$Lease.Checks; not_sent_retries=$Lease.NotSentRetries;
            updated_at=[DateTime]::UtcNow.ToString('o')}
    }
    catch { Write-Verbose ('Queue telemetry unavailable: ' + $_.Exception.GetType().Name) }
}

function Assert-EtxChannelReady {
    param([object]$Lease)
    $path = Join-Path $Lease.StatsRoot 'channel-health.json'
    if (-not (Test-Path -LiteralPath $path)) { return }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096) {
        throw 'ETX_CHANNEL_HEALTH_INVALID'
    }
    $saved = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($saved.version -ne 1) { throw 'ETX_CHANNEL_HEALTH_INVALID' }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0
    $Lease.RetryAfterSeconds = [Math]::Max(0,[Math]::Ceiling($saved.not_before-$now))
    if ($Lease.RetryAfterSeconds -gt 0) { throw 'ETX_CHANNEL_COOLDOWN' }
}

function Update-EtxChannelHealth {
    param([object]$Lease, [object]$Reply)
    if ($null -eq $Reply) { return }
    $errorCode = if ($Reply.PSObject.Properties['error']) { [string]$Reply.error } else { '' }
    $failure = $errorCode -in @('RPC_TIMEOUT_QUERY_SAME_ID','CLIPBOARD_IO_TIMEOUT',
        'CLIPBOARD_IO_PROCESS_EXITED','CLIPBOARD_OPEN_BUSY')
    $healthy = $Reply.PSObject.Properties['ok'] -and $Reply.ok -eq $true
    if (-not $healthy -and $Reply.PSObject.Properties['timings'] -and $Reply.timings.PSObject.Properties['rpc']) {
        $healthy = @($Reply.timings.rpc | Where-Object verify_seconds -gt 0).Count -gt 0
    }
    if ($failure -or $healthy) {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0
        Write-EtxQueueJson (Join-Path $Lease.StatsRoot 'channel-health.json') @{
            version=1; not_before=$(if ($failure) {$now+30} else {0});
            error=$(if ($failure) {$errorCode} else {''}); updated_at=$now}
    }
    $Lease.LastError = $errorCode
}

function Wait-EtxQueueMutex {
    param([object]$Lease, [Threading.Mutex]$Mutex, [string]$Phase)
    $segment = [Diagnostics.Stopwatch]::StartNew()
    $baseWait = $Lease.WaitSeconds
    $nextCheck = 0.0
    try {
        $milliseconds = 0
        while ($true) {
            if ($Lease.Watch.Elapsed.TotalSeconds -ge $Lease.TimeoutSeconds) { throw 'ETX_QUEUE_WAIT_TIMEOUT' }
            $acquired = $false
            try { $acquired = $Mutex.WaitOne($milliseconds) }
            catch [Threading.AbandonedMutexException] { $acquired = $true }
            if ($acquired) { return }
            $Lease.WaitSeconds = $baseWait + $segment.Elapsed.TotalSeconds
            if ($segment.Elapsed.TotalSeconds -ge $nextCheck) {
                $profile = Get-EtxQueueProfile $Lease.StatsRoot $Lease.Kind
                $Lease.CheckSeconds = $profile.CheckSeconds; $Lease.MeanSeconds = $profile.MeanSeconds
                $Lease.Checks++
                Set-EtxQueueState $Lease $Phase
                $nextCheck = $segment.Elapsed.TotalSeconds + $Lease.CheckSeconds
            }
            $remaining = $Lease.TimeoutSeconds - $Lease.Watch.Elapsed.TotalSeconds
            $untilCheck = $nextCheck - $segment.Elapsed.TotalSeconds
            $milliseconds = [int][Math]::Max(1, [Math]::Min(250, [Math]::Min($remaining*1000, $untilCheck*1000)))
        }
    }
    finally { $Lease.WaitSeconds = $baseWait + $segment.Elapsed.TotalSeconds }
}

function Wait-EtxPacketIdle {
    param([object]$Lease)
    # Probe availability, then RELEASE the core mutex before launching its child.
    # Holding it across child startup would deadlock the existing core.
    $packet = [Threading.Mutex]::new($false, $Lease.PacketName)
    $acquired = $false
    try {
        Wait-EtxQueueMutex $Lease $packet 'waiting_active_transfer'
        $acquired = $true
    }
    finally {
        if ($acquired) { $packet.ReleaseMutex() }
        $packet.Dispose()
    }
}

function Enter-EtxQueue {
    param([string]$Root, [string]$Kind, [string]$StatePath, [double]$TimeoutSeconds=600,
        [string]$QueueName='Local\ETX_X11_ConsumerQueueV1',
        [string]$PacketName='Local\ETX_X11_WindowsPacket')
    if ($Kind -notmatch '^[a-zA-Z0-9_-]{1,80}$') { throw 'Invalid queue operation kind' }
    $folder = Join-Path $Root '.work\x11\transport-queue'
    $pausePath = Join-Path $folder 'paused.json'
    if (Test-Path -LiteralPath $pausePath) {
        throw 'ETX_CHANNEL_PAUSED_FOR_RECOVERY'
    }
    $check = $folder
    while ($check -and $check.Length -ge $Root.Length) {
        if (Test-Path -LiteralPath $check) {
            if ((Get-Item -LiteralPath $check -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Invalid queue directory' }
        }
        $check = [IO.Path]::GetDirectoryName($check)
    }
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    if (-not $StatePath) { $StatePath = Join-Path $folder ('last-' + $PID + '.json') }
    $profile = Get-EtxQueueProfile $folder $Kind
    $lease = [pscustomobject]@{Mutex=[Threading.Mutex]::new($false,$QueueName); Held=$false;
        StatsRoot=$folder; Kind=$Kind; StatePath=$StatePath; TimeoutSeconds=$TimeoutSeconds;
        PacketName=$PacketName; Watch=[Diagnostics.Stopwatch]::StartNew(); WaitSeconds=0.0;
        CheckSeconds=$profile.CheckSeconds; MeanSeconds=$profile.MeanSeconds; Checks=0;
        NotSentRetries=0; Phase='waiting_queue'; LastError=''; RetryAfterSeconds=0}
    try {
        Set-EtxQueueState $lease 'waiting_queue'
        Wait-EtxQueueMutex $lease $lease.Mutex 'waiting_queue'
        $lease.Held = $true
        Assert-EtxChannelReady $lease
        Wait-EtxPacketIdle $lease
        Set-EtxQueueState $lease 'ready'
        return $lease
    }
    catch {
        Set-EtxQueueState $lease 'not_sent' $_.Exception.Message
        if ($lease.Held) { $lease.Mutex.ReleaseMutex() }
        $lease.Mutex.Dispose()
        throw
    }
}

function Exit-EtxQueue {
    param([object]$Lease, [bool]$Success=$false, [double]$ServiceSeconds=0, [bool]$Interrupted=$false)
    if ($null -eq $Lease) { return }
    try {
        # Queue time and user-copy pauses are never service-duration samples.
        if ($Success -and -not $Interrupted -and $ServiceSeconds -gt 0 -and $ServiceSeconds -le 3600) {
            try {
                $profile = Get-EtxQueueProfile $Lease.StatsRoot $Lease.Kind
                $samples = @(@($profile.Samples) + $ServiceSeconds | Select-Object -Last 20)
                Write-EtxQueueJson (Join-Path $Lease.StatsRoot ($Lease.Kind+'.json')) @{version=1; samples=$samples}
            }
            catch { Write-Verbose 'Queue duration sample could not be saved' }
        }
        if ($Lease.Phase -ne 'not_sent') {
            Set-EtxQueueState $Lease $(if ($Success) {'complete'} else {'finished'}) $Lease.LastError
        }
    }
    finally {
        if ($Lease.Held) { $Lease.Mutex.ReleaseMutex(); $Lease.Held=$false }
        $Lease.Mutex.Dispose()
    }
}
