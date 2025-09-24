# Tests


# DPAPI Blobs
Test blobs were created with PowerShell:
```powershell
Add-Type -AssemblyName System.Security
$data    = [Text.Encoding]::ASCII.GetBytes("test")
$encrypted_no_entropy = [Security.Cryptography.ProtectedData]::Protect($data, $null, 'CurrentUser')

$encrypted_with_entropy = [Security.Cryptography.ProtectedData]::Protect($data, [byte[]](1,2,3,4,5), 'CurrentUser')

Write-Host ("no entropy:`n" + [Convert]::ToBase64String($encrypted_no_entropy))
Write-Host ("`nwith entropy:`n" + [Convert]::ToBase64String($encrypted_no_entropy))
```