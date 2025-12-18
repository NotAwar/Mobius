#===================================================================================
# Mobius Client Installation Script for Windows
# 
# Usage:
#   iwr -useb https://install.mobius.com/install.ps1 | iex; `
#     Install-MobiusClient -Server "https://mobius.example.com" -EnrollmentKey "KEY"
#
# Or download and run:
#   .\install.ps1 -Server "URL" -EnrollmentKey "KEY"
#===================================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$Server,
    
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentKey,
    
    [string]$Version = "latest",
    
    [string]$InstallDir = "$env:ProgramFiles\Mobius",
    
    [string]$DownloadUrl = "https://releases.mobius.com"
)

$ErrorActionPreference = "Stop"

# Colors
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    $oldColor = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $Color
    Write-Output $Message
    $host.UI.RawUI.ForegroundColor = $oldColor
}

function Write-Header {
    Write-ColorOutput "`n================================================" "Cyan"
    Write-ColorOutput "  Mobius Client Installation" "Cyan"
    Write-ColorOutput "================================================`n" "Cyan"
}

function Write-Info {
    Write-ColorOutput "ℹ  $args" "Blue"
}

function Write-Success {
    Write-ColorOutput "✓  $args" "Green"
}

function Write-Warning {
    Write-ColorOutput "⚠  $args" "Yellow"
}

function Write-Error-Custom {
    Write-ColorOutput "✗  $args" "Red"
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Create-Directories {
    Write-Info "Creating directories..."
    
    $dirs = @(
        $InstallDir,
        "$env:ProgramData\Mobius",
        "$env:ProgramData\Mobius\config",
        "$env:ProgramData\Mobius\logs",
        "$env:ProgramData\Mobius\data"
    )
    
    foreach ($dir in $dirs) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directories created"
}

function Download-Binary {
    Write-Info "Downloading Mobius client..."
    
    $binaryName = "mobius-client-windows-amd64.exe"
    $downloadFile = "$DownloadUrl/$Version/${binaryName}.zip"
    $tempDir = "$env:TEMP\mobius-install"
    $zipFile = "$tempDir\mobius-client.zip"
    
    # Create temp directory
    if (!(Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    }
    
    try {
        # Download
        Write-Info "Downloading from: $downloadFile"
        Invoke-WebRequest -Uri $downloadFile -OutFile $zipFile -UseBasicParsing
        
        # Extract
        Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force
        
        # Install
        $exePath = "$tempDir\$binaryName"
        if (Test-Path $exePath) {
            Copy-Item -Path $exePath -Destination "$InstallDir\mobius-client.exe" -Force
        } else {
            throw "Binary not found in archive"
        }
        
        Write-Success "Binary installed to $InstallDir\mobius-client.exe"
    }
    catch {
        Write-Error-Custom "Failed to download binary: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Enroll-Client {
    Write-Info "Enrolling client with server..."
    
    $configPath = "$env:ProgramData\Mobius\config\client.yaml"
    
    try {
        & "$InstallDir\mobius-client.exe" enroll `
            --server="$Server" `
            --key="$EnrollmentKey" `
            --config="$configPath"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Enrollment command failed with exit code $LASTEXITCODE"
        }
        
        Write-Success "Client enrolled successfully"
    }
    catch {
        Write-Error-Custom "Enrollment failed: $_"
        throw
    }
}

function Install-Service {
    Write-Info "Installing Windows service..."
    
    $serviceName = "MobiusClient"
    $serviceDisplayName = "Mobius Client Daemon"
    $serviceDescription = "Mobius MDM client daemon for remote device management"
    $binaryPath = "$InstallDir\mobius-client.exe"
    $configPath = "$env:ProgramData\Mobius\config\client.yaml"
    
    # Check if service exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "Service already exists, removing..."
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Create service
    try {
        $result = sc.exe create $serviceName `
            binPath= "`"$binaryPath`" start --config=`"$configPath`"" `
            start= auto `
            DisplayName= "$serviceDisplayName"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create service: $result"
        }
        
        # Set description
        sc.exe description $serviceName "$serviceDescription" | Out-Null
        
        # Set recovery options (restart on failure)
        sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
        
        Write-Success "Service installed"
    }
    catch {
        Write-Error-Custom "Failed to install service: $_"
        throw
    }
}

function Start-Service-Custom {
    Write-Info "Starting Mobius client service..."
    
    try {
        Start-Service -Name "MobiusClient"
        Write-Success "Service started"
        
        # Wait a moment and check status
        Start-Sleep -Seconds 2
        $service = Get-Service -Name "MobiusClient"
        if ($service.Status -eq "Running") {
            Write-Success "Service is running"
        } else {
            Write-Warning "Service status: $($service.Status)"
        }
    }
    catch {
        Write-Error-Custom "Failed to start service: $_"
        throw
    }
}

function Add-To-Path {
    Write-Info "Adding to system PATH..."
    
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$InstallDir*") {
        $newPath = "$currentPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        Write-Success "Added to PATH"
    } else {
        Write-Info "Already in PATH"
    }
}

function Show-Status {
    Write-ColorOutput "`n================================================" "Green"
    Write-ColorOutput "  Installation Complete!" "Green"
    Write-ColorOutput "================================================`n" "Green"
    
    Write-Output "Service status:"
    $service = Get-Service -Name "MobiusClient" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Output "  Name:   $($service.Name)"
        Write-Output "  Status: $($service.Status)"
        Write-Output "  Start:  $($service.StartType)"
    } else {
        Write-Output "  Service not found"
    }
    
    Write-Output "`nLogs available at: $env:ProgramData\Mobius\logs\"
    Write-Output "Configuration: $env:ProgramData\Mobius\config\client.yaml"
    
    Write-Output "`nUseful commands:"
    Write-Output "  View service:  Get-Service MobiusClient"
    Write-Output "  Start:         Start-Service MobiusClient"
    Write-Output "  Stop:          Stop-Service MobiusClient"
    Write-Output "  Restart:       Restart-Service MobiusClient"
    Write-Output "  View logs:     Get-Content `"$env:ProgramData\Mobius\logs\client.log`" -Tail 50 -Wait"
    Write-Output ""
}

# Main installation function
function Install-MobiusClient {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        
        [Parameter(Mandatory=$true)]
        [string]$EnrollmentKey,
        
        [string]$Version = "latest"
    )
    
    Write-Header
    
    # Check admin
    if (!(Test-Administrator)) {
        Write-Error-Custom "This script must be run as Administrator"
        Write-Output "Please run PowerShell as Administrator and try again."
        exit 1
    }
    
    try {
        Write-Info "Detected OS: $([Environment]::OSVersion.VersionString)"
        Write-Info "Architecture: $([Environment]::Is64BitOperatingSystem -eq $true ? 'x64' : 'x86')"
        
        if (!([Environment]::Is64BitOperatingSystem)) {
            Write-Error-Custom "32-bit Windows is not supported"
            exit 1
        }
        
        Create-Directories
        Download-Binary
        Enroll-Client
        Install-Service
        Add-To-Path
        Start-Service-Custom
        Show-Status
        
        Write-ColorOutput "`n✓ Installation completed successfully!`n" "Green"
    }
    catch {
        Write-Error-Custom "Installation failed: $_"
        Write-Output $_.ScriptStackTrace
        exit 1
    }
}

# If running as script (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    if ($Server -and $EnrollmentKey) {
        Install-MobiusClient -Server $Server -EnrollmentKey $EnrollmentKey -Version $Version
    } else {
        Write-Output "Usage:"
        Write-Output "  .\install.ps1 -Server 'https://mobius.example.com' -EnrollmentKey 'YOUR_KEY'"
        Write-Output ""
        Write-Output "Or import and call the function:"
        Write-Output "  . .\install.ps1"
        Write-Output "  Install-MobiusClient -Server 'URL' -EnrollmentKey 'KEY'"
        exit 1
    }
}

# Export function for dot-sourcing
Export-ModuleMember -Function Install-MobiusClient
