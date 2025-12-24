# Windows SSH-Based JEA

![PowerShell 7](https://img.shields.io/badge/PowerShell-7+-blue) ![Windows](https://img.shields.io/badge/OS-Windows-lightgrey)

## Table of Contents

1. [Create the JEA User](#1%EF%B8%8F⃣-create-the-jea-user)
2. [Prepare the JEA Folder](#2%EF%B8%8F⃣-prepare-the-jea-folder-structure)
3. [Generate SSH Keys for Admin-JEA](#3%EF%B8%8F⃣-generate-ssh-keys-for-admin-jea)
4. [Install and Configure OpenSSH](#4%EF%B8%8F⃣-install-and-configure-openssh)
5. [Place JEA Runner and Scripts](#5%EF%B8%8F⃣-place-jea-runner-and-scripts)
6. [Test the Setup](#6%EF%B8%8F⃣-test-the-setup)
7. [Notes / Requirements](#notes--requirements)

---

## 1️⃣ Create the JEA User

* Create a dedicated Windows user (e.g., `Admin-JEA`) with a secure password.
* Give the user administrative privileges.
* This user will **only be used as the SSH entry point** to run allowed commands through JEA.

---

## 2️⃣ Prepare the JEA Folder Structure

* Create folder:

```text
C:\ProgramData\Admin-JEA
```

* Inside it, create:

```text
Scripts\
Scripts.json
id_ed25519  # private key for SSH login
```

* **Important:** Ensure the entire ProgramData folder and all children are **read-only for normal users**. Only `Administrators` and `SYSTEM` should have write permissions.

---

## 3️⃣ Generate SSH Keys for Admin-JEA

* Log in as `Admin-JEA` and run:

```powershell
ssh-keygen
```

* Add the **public key** to:

```text
C:\Users\Admin-JEA\.ssh\authorized_keys
```

* Copy the **private key** to:

```text
C:\ProgramData\Admin-JEA\id_ed25519
```

* Users who need SSH access to JEA should copy this private key locally.

---

## 4️⃣ Install and Configure OpenSSH

1. Install OpenSSH Server if not already installed:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

2. Edit `sshd_config` and **comment out** any existing authorized key settings for groups:

```text
# Match Group administrators
#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

3. Add a `Match User` block for Admin-JEA:

```text
Match User Admin-JEA
    ForceCommand pwsh C:/ProgramData/Admin-JEA/JEARunner.ps1
    PubkeyAuthentication yes
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitTTY no
```

4. Ensure OpenSSH services are **started and automatic**:

```powershell
Set-Service sshd -StartupType Automatic
Start-Service sshd

Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

> Notes:
>
> * ForceCommand ensures users cannot bypass the JEA runner.
> * Only SSH key login is allowed; keyboard-interactive and password logins are disabled.

---

## 5️⃣ Place JEA Runner and Scripts

### `JEARunner.ps1`

```powershell
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Fail ($Message, $Code = 1) {
    Write-Error $Message
    exit $Code
}

$raw = [Environment]::GetEnvironmentVariable('SSH_ORIGINAL_COMMAND')
if (-not $raw) {
    Fail "SSH_ORIGINAL_COMMAND is not set"
}

try {
    $request = $raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    Fail "SSH_ORIGINAL_COMMAND is not valid JSON"
}

$command = $null
try {
    $command = [string]$request.Command
} catch {
    Fail "Command not provided"
}

$userName = $null
try {
    $userName = [string]$request.User
} catch {
    Fail "User not provided"
}

$passwordPlain = $null
try {
    $passwordPlain = [string]$request.Password
} catch {
    $passwordPlain = ""
}

$securePassword = $null
if ($passwordPlain.Length -eq 0) {
    $securePassword = New-Object -TypeName System.Security.SecureString
} else {
    $securePassword = ConvertTo-SecureString $passwordPlain -AsPlainText -Force
}

if ($null -ne $request.PSObject.Properties['CommandArgs']) {
    $commandArgs = @($request.CommandArgs)
} else {
    $commandArgs = @()
}

try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $ctx = New-Object `
        System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Machine
        )

    if (-not $ctx.ValidateCredentials($userName, $passwordPlain)) {
        Fail "Invalid username or password"
    }
} catch {
    Fail "User validation failed: $($_.Exception.Message)"
} finally {
    $passwordPlain = $null
    [GC]::Collect()
}

$baseDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$mapPath    = Join-Path $baseDir 'Scripts.json'
$scriptsDir = Join-Path $baseDir 'Scripts'

if (-not (Test-Path $mapPath)) {
    Fail "Scripts.json not found"
}

$commandMap = Get-Content $mapPath -Raw | ConvertFrom-Json
if (-not $commandMap.PSObject.Properties[$command]) {
    Fail "Command '$command' not allowed"
}

$scriptName = $commandMap.$command
$scriptPath = Join-Path $scriptsDir $scriptName

if (-not (Test-Path $scriptPath)) {
    Fail "Script '$scriptName' not found"
}

try {
    $result = & $scriptPath `
        -User $userName `
        -SecurePassword $securePassword `
        -CommandArgs $commandArgs
} catch {
    Fail "JEA script execution failed: $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 5 -Compress
exit 0
```

### Example USBIPD Script (`USBIPD.ps1`)

```powershell
param(
    [Parameter(Mandatory)] [string]$User,
    [Parameter(Mandatory)] [SecureString]$SecurePassword,
    [string[]]$CommandArgs
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

try {
    if (-not $CommandArgs -or $CommandArgs.Count -lt 3 -or $CommandArgs.Count -gt 4) {
        return [pscustomobject]@{
            StdOut   = ""
            StdErr   = "Invalid arguments. Expected: [bind|unbind] [bus|hw] <value> [force]"
            ExitCode = 1
        }
    }

    $action     = $CommandArgs[0]
    $targetType = $CommandArgs[1]
    $value      = $CommandArgs[2]
    $forceFlag  = if ($CommandArgs.Count -eq 4) { $CommandArgs[3] } else { $null }

    if ($action -notin @('bind', 'unbind')) {
        return [pscustomobject]@{
            StdOut   = ""
            StdErr   = "Invalid action. Only 'bind' or 'unbind' are allowed."
            ExitCode = 1
        }
    }

    if ($targetType -notin @('bus', 'hw')) {
        return [pscustomobject]@{
            StdOut   = ""
            StdErr   = "Invalid target type. Only 'bus' or 'hw' are allowed."
            ExitCode = 1
        }
    }

    if ($forceFlag) {
        if ($forceFlag -ne 'force') {
            return [pscustomobject]@{
                StdOut   = ""
                StdErr   = "Invalid argument '$forceFlag'. Only 'force' is allowed as the optional 4th argument."
                ExitCode = 1
            }
        }
        if ($action -ne 'bind') {
            return [pscustomobject]@{
                StdOut   = ""
                StdErr   = "'force' is only allowed with 'bind'."
                ExitCode = 1
            }
        }
    }

    $exe = Get-Command 'usbipd.exe' -ErrorAction Stop
    $exePath = $exe.Source

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $exePath
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    # ---- construct safe usbipd arguments ----
    $psi.ArgumentList.Add($action.ToLower())

    switch ($targetType) {
        'bus' { $psi.ArgumentList.Add('-b') }
        'hw'  { $psi.ArgumentList.Add('-i') }
    }

    $psi.ArgumentList.Add($value)

    if ($forceFlag) {
        $psi.ArgumentList.Add('--force')
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode

    [pscustomobject]@{
        StdOut   = $stdout.TrimEnd()
        StdErr   = $stderr.TrimEnd()
        ExitCode = $exitCode
    }
} catch {
    [pscustomobject]@{
        StdOut   = ""
        StdErr   = $_.Exception.Message
        ExitCode = 1
    }
}
```

### `Scripts.json` Example

```json
{
  "USBIPD": "USBIPD.ps1"
}
```

---

## 6️⃣ Test the Setup

```powershell
ssh -i .\.ssh\admin-jea-id_ed25519 admin-jea@localhost $(ConvertTo-Json @{
    Command = "USBIPD"
    User = "Faisal Al-Humaimidi"
    Password = "userpassword"
    CommandArgs = "--help"
})
```

* Only allowed commands run.
* User password is validated inside the JEA runner.
* Output is returned as JSON with `StdOut`, `StdErr`, `ExitCode`.

---

## Notes / Requirements

* **PowerShell 7+** is required (for `ArgumentList` support).
* Only **SSH key login** is allowed; keyboard-interactive and password logins are disabled.
* ProgramData folder (`C:\ProgramData\Admin-JEA`) and its children must be **read-only for normal users**.
* All login enforcement is handled inside the JEA runner; no additional console/RDP/network restrictions are required.
* **OpenSSH SSH Server** and **OpenSSH Authentication Agent** must be set to **Automatic** and started **after** updating `sshd_config`.
