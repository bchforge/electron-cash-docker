param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("backup", "restore")]
    [string]$Operation,
    [Parameter(Position = 1, Mandatory = $true)]
    [string]$RawName
)

$ErrorActionPreference = "Stop"
$oldErrorActionPreference = $ErrorActionPreference
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = (Resolve-Path (Join-Path $scriptDir "..")).Path
$backupDir = if ($env:BACKUP_DIR) { $env:BACKUP_DIR } else { Join-Path $projectDir "backups" }
$stateHome = if ($env:XDG_STATE_HOME) { $env:XDG_STATE_HOME } else { Join-Path $HOME ".local/state" }
$stateDir = Join-Path $stateHome "electron-cash-docker"
$pendingPath = Join-Path $stateDir "restore-pending"

function Fail([string]$Message) {
    throw $Message
}

if ($RawName -notmatch '^[A-Za-z0-9._-]+$' -or $RawName -in @(".", "..") -or $RawName.Contains("..")) {
    Fail "Invalid backup name."
}
$name = if ($RawName.EndsWith(".ecd.gpg")) { $RawName.Substring(0, $RawName.Length - 8) } else { $RawName }
if ([string]::IsNullOrWhiteSpace($name) -or $name -notmatch '^[A-Za-z0-9._-]+$' -or $name.Contains("..")) {
    Fail "Invalid backup name."
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "Docker is required." }
& docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Compose v2 is required." }

if (Test-Path $backupDir -PathType Leaf) { Fail "Backup directory is not safe." }
$backupDirectoryItem = Get-Item -LiteralPath $backupDir -Force -ErrorAction SilentlyContinue
if ($null -ne $backupDirectoryItem -and ($backupDirectoryItem.LinkType -or ($backupDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint))) { Fail "Backup directory is not safe." }
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$composeEnvironment = & docker compose --project-directory $projectDir config --environment
if ($LASTEXITCODE -ne 0) { Fail "Compose environment is unavailable." }
$composeValues = @{}
foreach ($line in $composeEnvironment) {
    if ($line -match '^([^=]+)=(.*)$') { $composeValues[$Matches[1]] = $Matches[2] }
}
$image = if ($env:IMAGE) { $env:IMAGE } elseif ($composeValues["ELECTRON_CASH_IMAGE"]) { $composeValues["ELECTRON_CASH_IMAGE"] } else { $null }
$ecVersion = if ($env:EC_VERSION) { $env:EC_VERSION } elseif ($composeValues["EC_VERSION"]) { $composeValues["EC_VERSION"] } else { "4.4.6" }
$testnet4 = if ($env:TESTNET4) { $env:TESTNET4 } elseif ($composeValues["TESTNET4"]) { $composeValues["TESTNET4"] } else { "false" }
$walletVolume = if ($env:ECD_WALLET_VOLUME) { $env:ECD_WALLET_VOLUME } elseif ($composeValues["ECD_WALLET_VOLUME"]) { $composeValues["ECD_WALLET_VOLUME"] } else { "bchforge-electron-cash-data" }
$image = if ($image) { $image } else { "electron-cash:$ecVersion" }
if ($walletVolume -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { Fail "Compose selected an unsafe wallet volume name." }
if ($testnet4 -eq "true") { $backupNetwork = "testnet4" } elseif ($testnet4 -eq "false") { $backupNetwork = "mainnet" } else { Fail "Compose selected an invalid Electron Cash network." }
& docker volume inspect $walletVolume *> $null
if ($LASTEXITCODE -ne 0) { Fail "The configured Electron Cash wallet volume does not exist. Start the stack first." }

$projectId = [regex]::Replace((Split-Path -Leaf $projectDir), '[^A-Za-z0-9._-]', '-')
if ([string]::IsNullOrWhiteSpace($projectId)) { $projectId = "electron-cash-docker" }
$rollbackManagedLabel = "com.bchforge.electron-cash-docker.managed"
$rollbackProjectLabel = "com.bchforge.electron-cash-docker.project"
$script:backupWasRunning = $false
$script:restoreActive = $false
$script:rollbackVolume = ""
$script:passphrase = $null

function Is-Running {
    $script:runningContainer = (& docker compose --project-directory $projectDir ps -q --status running electron-cash).Trim()
    return -not [string]::IsNullOrWhiteSpace($script:runningContainer)
}

function Stop-Service {
    if (Is-Running) {
        & docker compose --project-directory $projectDir stop electron-cash *> $null
        if ($LASTEXITCODE -ne 0) { throw "Could not stop Electron Cash." }
    }
    $attempts = 0
    while ((Is-Running) -and $attempts -lt 30) {
        Start-Sleep -Seconds 1
        $attempts++
    }
    if (Is-Running) { throw "Electron Cash did not stop." }
}

function Wait-Healthy {
    $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 180
    $lastState = "not-started"
    while ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $deadline) {
        $container = (& docker compose --project-directory $projectDir ps -q --status running electron-cash).Trim()
        if ($container) {
            $lastState = (& docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' $container).Trim()
            if ($lastState -eq "running|healthy") { return }
            if ($lastState -match '^(exited|dead)\|' -or $lastState -match '\|unhealthy$') { break }
        }
        Start-Sleep -Seconds 2
    }
    throw "Electron Cash did not become healthy ($lastState)."
}

function Start-Service-Healthy {
    & docker compose --project-directory $projectDir up -d --no-deps electron-cash *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not start Electron Cash." }
    Wait-Healthy
}

function Ensure-Stopped {
    if (Is-Running) { Stop-Service }
}

function Ensure-Volume-Unused {
    $attempts = 0
    do {
        $users = (& docker ps -q --filter "volume=$walletVolume").Trim()
        if (-not $users) { return }
        Start-Sleep -Seconds 1
        $attempts++
    } while ($attempts -lt 30)
    throw "The wallet volume is still in use."
}

function New-SecurityArgs {
    return @(
        "--pull=never", "--rm", "--network", "none", "--read-only",
        "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--cap-add=CHOWN",
        "--cap-add=FOWNER", "--security-opt", "no-new-privileges:true",
        "--user", "0:0", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"
    )
}

function Invoke-Helper([string[]]$Arguments, [string]$InputText = $null) {
    if ($null -ne $InputText) { $InputText | & docker @Arguments } else { & docker @Arguments }
    if ($LASTEXITCODE -ne 0) { throw "Docker backup helper failed with exit code $LASTEXITCODE." }
}

function Invoke-Create {
    $arguments = @(New-SecurityArgs) + @(
        "-i",
        "--mount", "type=volume,src=$walletVolume,dst=/wallet,readonly",
        "--mount", "type=bind,src=$backupDir,dst=/backups",
        "-e", "BACKUP_NETWORK=$backupNetwork", "-e", "EC_VERSION=$ecVersion",
        "--entrypoint", "/home/electroncash/backup.sh", $image,
        "create", "/backups/$name.ecd.gpg"
    )
    Invoke-Helper $arguments $script:passphrase
}

function Invoke-Verify {
    $arguments = @(New-SecurityArgs) + @(
        "-i",
        "--mount", "type=bind,src=$backupDir,dst=/backups,readonly",
        "-e", "BACKUP_NETWORK=$backupNetwork", "-e", "EC_VERSION=$ecVersion",
        "--entrypoint", "/home/electroncash/backup.sh", $image,
        "verify", "/backups/$name.ecd.gpg"
    )
    Invoke-Helper $arguments $script:passphrase
}

function Invoke-Snapshot {
    $arguments = @(New-SecurityArgs) + @(
        "--mount", "type=volume,src=$walletVolume,dst=/wallet,readonly",
        "--mount", "type=volume,src=$script:rollbackVolume,dst=/snapshot",
        "-e", "BACKUP_NETWORK=$backupNetwork", "-e", "EC_VERSION=$ecVersion",
        "--entrypoint", "/home/electroncash/backup.sh", $image, "snapshot", "/snapshot"
    )
    Invoke-Helper $arguments
}

function Invoke-Replace {
    $arguments = @(New-SecurityArgs) + @(
        "-i",
        "--mount", "type=volume,src=$walletVolume,dst=/wallet",
        "--mount", "type=bind,src=$backupDir,dst=/backups,readonly",
        "-e", "BACKUP_NETWORK=$backupNetwork", "-e", "EC_VERSION=$ecVersion",
        "--entrypoint", "/home/electroncash/backup.sh", $image,
        "replace", "/backups/$name.ecd.gpg"
    )
    Invoke-Helper $arguments $script:passphrase
}

function Invoke-RestoreSnapshot {
    $arguments = @(New-SecurityArgs) + @(
        "--mount", "type=volume,src=$walletVolume,dst=/wallet",
        "--mount", "type=volume,src=$script:rollbackVolume,dst=/snapshot,readonly",
        "-e", "BACKUP_NETWORK=$backupNetwork", "-e", "EC_VERSION=$ecVersion",
        "--entrypoint", "/home/electroncash/backup.sh", $image, "restore-snapshot", "/snapshot"
    )
    Invoke-Helper $arguments
}

function Write-Pending {
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    $directory = Get-Item -LiteralPath $stateDir
    if ($directory.LinkType -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Restore state directory is not safe." }
    $existingMarker = Get-Item -LiteralPath $pendingPath -Force -ErrorAction SilentlyContinue
    if ($null -ne $existingMarker) {
        throw "Restore interruption marker already exists; refusing to overwrite it."
    }
    $temporary = Join-Path $stateDir (".restore-pending.{0}.{1}" -f $PID, [guid]::NewGuid().ToString("N"))
    try {
        @(
            "electron-cash-docker-restore-pending-v1",
            "wallet_volume=$walletVolume",
            "rollback_volume=$script:rollbackVolume",
            "service_running=$script:backupWasRunning"
        ) | Set-Content -LiteralPath $temporary -Encoding ascii
        Move-Item -LiteralPath $temporary -Destination $pendingPath
    }
    finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $temporary
    }
}

function Read-Pending {
    $marker = Get-Item -LiteralPath $pendingPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $marker) { return $null }
    if ($marker.LinkType -or ($marker.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $marker.PSIsContainer) { throw "Restore marker is not a safe regular file; refusing recovery." }
    $values = @{}
    $headerSeen = $false
    foreach ($line in Get-Content -LiteralPath $pendingPath) {
        if ($line -eq "electron-cash-docker-restore-pending-v1") {
            if ($headerSeen) { throw "Restore marker is invalid; refusing duplicate fields." }
            $values.header = $line
            $headerSeen = $true
            continue
        }
        if ($line -match '^(wallet_volume|rollback_volume|service_running)=(.*)$') {
            if ($values.ContainsKey($Matches[1])) { throw "Restore marker is invalid; refusing duplicate fields." }
            $values[$Matches[1]] = $Matches[2]
            continue
        }
        if ($line) { throw "Restore marker is invalid; refusing to guess wallet state." }
    }
    if ($values.header -ne "electron-cash-docker-restore-pending-v1" -or
        $values.wallet_volume -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or
        $values.rollback_volume -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or
        $values.service_running -notin @("True", "False", "true", "false")) {
        throw "Restore marker is invalid."
    }
    if ($values.wallet_volume -ne $walletVolume) { throw "Compose wallet selection changed during an interrupted restore." }
    return [pscustomobject]@{
        Wallet = $values.wallet_volume
        Rollback = $values.rollback_volume
        Running = $values.service_running -eq "True" -or $values.service_running -eq "true"
    }
}

function Assert-RollbackVolume([string]$Volume) {
    if ($Volume -eq $walletVolume) { throw "Restore rollback volume matches the live wallet." }
    $labels = (& docker volume inspect --format '{{index .Labels "com.bchforge.electron-cash-docker.managed"}}|{{index .Labels "com.bchforge.electron-cash-docker.project"}}' $Volume 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $labels -ne "rollback|$projectId") { throw "Restore rollback volume is not owned by this installation." }
}

function Remove-Rollback {
    if (-not $script:rollbackVolume) { return }
    & docker volume rm $script:rollbackVolume *> $null
    if ($LASTEXITCODE -ne 0) { throw "Temporary rollback cleanup failed." }
    $script:rollbackVolume = ""
}

function Restore-PriorState {
    if ($script:backupWasRunning) { Start-Service-Healthy } else { Ensure-Stopped }
}

function Rollback([string]$Reason) {
    [Console]::Error.WriteLine("[!] Restore failed: $Reason")
    Stop-Service
    Ensure-Volume-Unused
    Invoke-RestoreSnapshot
    Restore-PriorState
    Remove-Rollback
    Remove-Item -Force -ErrorAction SilentlyContinue $pendingPath
    [Console]::Error.WriteLine("[+] Previous wallet restored; Electron Cash returned to its prior state.")
}

function Recover-Pending {
    $pending = Read-Pending
    if ($null -eq $pending) { return }
    & docker volume inspect $pending.Rollback *> $null
    if ($LASTEXITCODE -ne 0) { throw "An interrupted restore has no rollback snapshot; refusing to guess." }
    Assert-RollbackVolume $pending.Rollback
    $script:rollbackVolume = $pending.Rollback
    $script:backupWasRunning = $pending.Running
    [Console]::Error.WriteLine("[!] An interrupted restore was found. Restoring its saved wallet before continuing.")
    Rollback "interrupted restore"
}

function Read-Secret([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

try {
    Recover-Pending
    $archive = Join-Path $backupDir "$name.ecd.gpg"
    $archiveItem = Get-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    $archiveExists = $null -ne $archiveItem
    if ($archiveExists -and ($archiveItem.LinkType -or ($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $archiveItem.PSIsContainer)) {
        Fail "Backup is not a safe regular file: $archive"
    }
    if ($Operation -eq "backup" -and $archiveExists) { Fail "Backup already exists: $archive" }
    if ($Operation -eq "restore" -and -not $archiveExists) { Fail "Backup is missing: $archive" }
    $script:backupWasRunning = Is-Running

    if ($Operation -eq "backup") {
        $first = Read-Secret "Enter backup password"
        $second = Read-Secret "Confirm backup password"
        if ($first -ne $second) { Fail "Backup passwords do not match." }
        $script:passphrase = $first
        if ($script:backupWasRunning) { Stop-Service } else { [Console]::Error.WriteLine("[*] Electron Cash is stopped; it will remain stopped.") }
        Ensure-Volume-Unused
        Invoke-Create
        if ($script:backupWasRunning) { Start-Service-Healthy }
        $script:passphrase = $null
        Write-Output "[+] Backup created: $archive"
        exit 0
    }

    [Console]::Error.WriteLine("Electron Cash Docker restore")
    [Console]::Error.WriteLine("Backup: $name")
    [Console]::Error.WriteLine("")
    [Console]::Error.WriteLine("WARNING")
    [Console]::Error.WriteLine("Restoring this backup will replace the active wallet.")
    if ($script:backupWasRunning) { [Console]::Error.WriteLine("Electron Cash is running and will be stopped temporarily.") }
    else { [Console]::Error.WriteLine("Electron Cash is currently stopped.") }
    [Console]::Error.WriteLine("The current wallet will be saved for automatic rollback.")
    if ((Read-Host "Continue? [y/N]") -notmatch '^(?i:y|yes)$') {
        [Console]::Error.WriteLine("Restore cancelled.")
        [Console]::Error.WriteLine("No changes were made.")
        exit 0
    }
    $script:passphrase = Read-Secret "Enter backup password"
    Invoke-Verify
    $script:restoreActive = $true
    Stop-Service
    Ensure-Volume-Unused
    $script:rollbackVolume = (& docker volume create --label "$rollbackManagedLabel=rollback" --label "$rollbackProjectLabel=$projectId").Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not create the temporary rollback snapshot." }
    if ($script:rollbackVolume -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw "Docker returned an unsafe rollback volume name." }
    Assert-RollbackVolume $script:rollbackVolume
    Invoke-Snapshot
    Write-Pending
    Invoke-Replace
    if ($script:backupWasRunning) { Start-Service-Healthy } else { Ensure-Stopped }
    Remove-Rollback
    Remove-Item -Force -ErrorAction SilentlyContinue $pendingPath
    $script:passphrase = $null
    Write-Output "[+] Restore completed successfully: $archive"
    exit 0
}
catch {
    $message = $_.Exception.Message
    if ($script:restoreActive -and $script:rollbackVolume -and (Test-Path $pendingPath -PathType Leaf)) {
        try { Rollback $message } catch { [Console]::Error.WriteLine("[!] Automatic rollback failed; marker and snapshot were preserved: $($_.Exception.Message)") }
    }
    elseif ($script:restoreActive) {
        try { Restore-PriorState; Remove-Rollback } catch { [Console]::Error.WriteLine("[!] Service recovery failed: $($_.Exception.Message)") }
    }
    elseif ($Operation -eq "backup") {
        try { Restore-PriorState } catch { [Console]::Error.WriteLine("[!] Service recovery failed: $($_.Exception.Message)") }
    }
    [Console]::Error.WriteLine("[!] $message")
    exit 1
}
finally {
    $script:passphrase = $null
}
