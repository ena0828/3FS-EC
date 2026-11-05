#Requires -Version 5.1
<#
.SYNOPSIS
Read-only Windows memory and backing-volume preflight for the native V2 lab.
.DESCRIPTION
Does not invoke WSL, start services, inspect file contents, create files or
modify disks. SwapFile and DataPath must identify administrator-confirmed
backing paths; this script cannot infer which live WSL device uses a VHDX.
#>
[CmdletBinding()]
param(
    [string] $SwapFile = '',
    [string[]] $DataPath = @(),
    [ValidateRange(1, 1024)] [int] $MinAvailableMemoryGiB = 3,
    [ValidateRange(1, 1048576)] [int] $MinVolumeFreeGiB = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$preflightProblems = [System.Collections.Generic.List[string]]::new()
$preflightPaths = [System.Collections.Generic.List[object]]::new()
$preflightVolumes = @{}
$preflightMemory = $null

function Get-PreflightVolume {
    param([hashtable] $Selector)
    # The job belongs to this read-only query. A timeout cancels this query,
    # never a WSL process, virtual disk, service or user process.
    $preflightVolumeJob = Get-Volume @Selector -AsJob -ErrorAction Stop
    try {
        if ($null -eq (Wait-Job -Job $preflightVolumeJob -Timeout 15)) {
            Stop-Job -Job $preflightVolumeJob -ErrorAction SilentlyContinue
            throw 'Volume metadata query timed out; no successful preflight can be reported.'
        }
        $preflightFound = @(Receive-Job -Job $preflightVolumeJob -ErrorAction Stop)
        if ($preflightFound.Count -ne 1) {
            throw 'Expected exactly one actual backing volume.'
        }
        return $preflightFound[0]
    }
    finally {
        if ($preflightVolumeJob.State -eq 'Running') {
            Stop-Job -Job $preflightVolumeJob -ErrorAction SilentlyContinue
        }
        Remove-Job -Job $preflightVolumeJob -ErrorAction SilentlyContinue
    }
}

function Add-PreflightVolume {
    param([object] $Volume, [string] $Role, [string] $Path)
    $preflightVolumeId = [string] $Volume.UniqueId
    if ([string]::IsNullOrWhiteSpace($preflightVolumeId)) {
        throw 'Backing volume did not return a persistent volume identifier.'
    }
    if (-not $preflightVolumes.ContainsKey($preflightVolumeId)) {
        $preflightVolumes[$preflightVolumeId] = [ordered] @{
            volume_id = $preflightVolumeId
            drive_letter = [string] $Volume.DriveLetter
            filesystem = [string] $Volume.FileSystem
            health = [string] $Volume.HealthStatus
            capacity_bytes = [uint64] $Volume.Size
            available_bytes = [uint64] $Volume.SizeRemaining
            required_available_bytes = [uint64] $MinVolumeFreeGiB * 1GB
        }
        if ([uint64] $Volume.SizeRemaining -lt [uint64] $MinVolumeFreeGiB * 1GB) {
            $preflightProblems.Add("Backing volume $preflightVolumeId has less than $MinVolumeFreeGiB GiB free.")
        }
        if ([string] $Volume.HealthStatus -ne 'Healthy') {
            $preflightProblems.Add("Backing volume $preflightVolumeId does not report Healthy.")
        }
    }
    $preflightPaths.Add([ordered] @{role = $Role; path = $Path; volume_id = $preflightVolumeId})
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This script requires the Windows host; it must not run through WSL.'
    }
    $preflightOs = Get-CimInstance -ClassName Win32_OperatingSystem `
        -Property FreePhysicalMemory, TotalVisibleMemorySize, SystemDrive -OperationTimeoutSec 10
    $preflightMemory = [ordered] @{
        available_bytes = [uint64] $preflightOs.FreePhysicalMemory * 1KB
        visible_bytes = [uint64] $preflightOs.TotalVisibleMemorySize * 1KB
        required_available_bytes = [uint64] $MinAvailableMemoryGiB * 1GB
    }
    if ($preflightMemory.available_bytes -lt $preflightMemory.required_available_bytes) {
        $preflightProblems.Add("Windows has less than $MinAvailableMemoryGiB GiB of currently available physical memory.")
    }

    # Always check C separately. It is not assumed to contain Ubuntu or swap.
    Add-PreflightVolume (Get-PreflightVolume @{DriveLetter = 'C'}) 'windows_c_volume' 'C:\'
    if ([string] $preflightOs.SystemDrive -ne 'C:') {
        $preflightSystemLetter = ([string] $preflightOs.SystemDrive).TrimEnd(':')
        Add-PreflightVolume (Get-PreflightVolume @{DriveLetter = $preflightSystemLetter}) `
            'windows_system_volume' ([string] $preflightOs.SystemDrive + '\')
    }
    if ([string]::IsNullOrWhiteSpace($SwapFile)) {
        $preflightProblems.Add('Actual WSL swap backing is unknown: provide administrator-confirmed -SwapFile; no default is guessed.')
    }
    if ($DataPath.Count -eq 0) {
        $preflightProblems.Add('No WSL data/image backing paths supplied: provide -DataPath for each relevant VHDX/image/path.')
    }
    $preflightRequestedPaths = @()
    if (-not [string]::IsNullOrWhiteSpace($SwapFile)) {
        $preflightRequestedPaths += [ordered] @{role = 'declared_swap_backing'; path = $SwapFile; require_file = $true}
    }
    foreach ($preflightDataPath in $DataPath) {
        $preflightRequestedPaths += [ordered] @{role = 'declared_data_backing'; path = $preflightDataPath; require_file = $false}
    }
    foreach ($preflightRequested in $preflightRequestedPaths) {
        try {
            $preflightRequestedPath = [string] $preflightRequested.path
            if ($preflightRequestedPath -notmatch '^[A-Za-z]:[\\/]') {
                throw 'Use an explicit absolute local Windows path, not a relative path or UNC resource.'
            }
            $preflightItem = Get-Item -LiteralPath $preflightRequestedPath -Force
            if ($preflightItem.PSProvider.Name -ne 'FileSystem') {
                throw 'Backing path is not a filesystem object.'
            }
            if ($preflightRequested.require_file -and $preflightItem.PSIsContainer) {
                throw '-SwapFile must name the actual existing swap backing file, not its directory.'
            }
            if ($preflightItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Final backing path is redirected; provide the explicit actual target path.'
            }
            # FilePath resolves the actual containing volume, including parent
            # mount points. A drive-letter prefix alone is not sufficient.
            $preflightActualVolume = Get-PreflightVolume @{FilePath = $preflightItem.FullName}
            Add-PreflightVolume $preflightActualVolume ([string] $preflightRequested.role) $preflightItem.FullName
        }
        catch {
            $preflightProblems.Add("Cannot establish backing path '$($preflightRequested.path)': $($_.Exception.Message)")
        }
    }
}
catch {
    $preflightProblems.Add("Host observation failed: $($_.Exception.Message)")
}

$preflightReport = [ordered] @{
    schema = 1
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    status = $(if ($preflightProblems.Count -eq 0) {'ready_for_separate_guest_preflight'} else {'needs_attention'})
    memory = $preflightMemory
    backing_paths = @($preflightPaths.ToArray())
    volumes = @($preflightVolumes.Values)
    problems = @($preflightProblems.ToArray())
    backing_identity_source = 'explicit administrator paths; live WSL device-to-file association is not inferred'
    limitations = @('Free space does not prove the cause of prior swap I/O errors.',
        'Host volume space does not measure free space inside a VHDX or loop filesystem.',
        'This is a point-in-time observation, not a reservation or a promise against OOM.')
    wsl_invoked = $false
    services_started = $false
    files_modified = $false
}
$preflightReport | ConvertTo-Json -Depth 8
if ($preflightProblems.Count -ne 0) { exit 1 }
exit 0
