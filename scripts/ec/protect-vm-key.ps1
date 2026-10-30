#Requires -Version 7.0
param(
    [string]$VmDirectory = 'E:\3fsec\artifacts\vm'
)

$ErrorActionPreference = 'Stop'
$vmKey = Get-Item -LiteralPath (Join-Path $VmDirectory 'keys\id_ed25519')
if ($vmKey.PSIsContainer) {
    throw 'The SSH private key must be a file.'
}
$vmOwnerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$vmSystemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$vmAcl = Get-Acl -LiteralPath $vmKey.FullName
$vmAcl.SetAccessRuleProtection($true, $false)
foreach ($vmExistingRule in @($vmAcl.Access)) {
    $vmAcl.RemoveAccessRuleSpecific($vmExistingRule)
}
foreach ($vmSid in @($vmOwnerSid, $vmSystemSid)) {
    $vmRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $vmSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $vmAcl.AddAccessRule($vmRule)
}
[System.IO.FileSystemAclExtensions]::SetAccessControl($vmKey, $vmAcl)
Write-Output 'Task SSH key access is restricted to the current Windows user and SYSTEM.'
