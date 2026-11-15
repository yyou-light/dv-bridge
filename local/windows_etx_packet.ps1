[CmdletBinding()]
param(
    [ValidateSet('SessionRpc', 'SessionPair', 'SessionReadFiles')]
    [string]$Mode,

    [ValidateRange(1.0, 3600.0)]
    [double]$TimeoutSeconds = 30.0,

    [ValidateRange(65536, 1048576)]
    [int]$MaxClipboardBytes = 786432,

    [ValidateRange(1024, 786432)]
    [int]$MaxPayloadBytes = 573440,

    [ValidateRange(1, 786432)]
    [int]$MaxFileBytes = 524288,

    [ValidateRange(1, 16777216)]
    [int]$MaxBinaryFileBytes = 16777216,

    [ValidateRange(65536, 393216)]
    [int]$BinaryChunkBytes = 393216,

    [ValidateRange(30, 1800)]
    [int]$TransferTimeoutSeconds = 600,

    [switch]$RequireChange,

    [switch]$AllowExistingPacket,

    [string]$PatchJsonPath,

    [string]$OutputPath,

    [string]$ExpectedRequestId,

    [string]$SessionConfig,

    [string]$SessionRequest,

    [string]$Fingerprint,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Session transport lives in the canonical Python core. Legacy modes below
# retain their original implementation and independent validation.
if ($Mode -in @('SessionRpc', 'SessionPair', 'SessionReadFiles')) {
    if ($SelfTest -or $PatchJsonPath -or $ExpectedRequestId -or $RequireChange -or $AllowExistingPacket) {
        throw 'Session mode cannot be combined with legacy packet arguments'
    }
    if (-not $SessionConfig -or -not $OutputPath) {
        throw 'Session mode requires configuration and response paths'
    }
    $launcherStartMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $sessionClient = Join-Path $PSScriptRoot 'windows_session.py'
    if (-not (Test-Path -LiteralPath $sessionClient -PathType Leaf)) {
        throw 'Canonical session client is not installed'
    }
    $python = (Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $sessionArguments = @($sessionClient)
    if ($Mode -eq 'SessionPair') {
        if (-not $Fingerprint -or $SessionRequest) { throw 'Pair requires only a fingerprint' }
        $sessionArguments += @('pair', '--fingerprint', $Fingerprint)
    }
    else {
        if (-not $SessionRequest -or $Fingerprint) { throw 'RPC requires only a request file' }
        $clientOperation = if ($Mode -eq 'SessionReadFiles') { 'read-files' } else { 'rpc' }
        $sessionArguments += @($clientOperation, '--request-file', $SessionRequest)
    }
    $sessionArguments += @('--config', $SessionConfig, '--response-file', $OutputPath, '--launcher-start-ms', $launcherStartMs)
    & $python @sessionArguments
    exit $LASTEXITCODE
}

throw 'This baseline exposes persistent session operations only'
