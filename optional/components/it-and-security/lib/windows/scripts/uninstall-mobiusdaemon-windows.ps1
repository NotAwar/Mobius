# Please don't delete. This script is referenced in the guide here: https://mobiusmdm.com/guides/how-to-uninstall-mobiusdaemon

function Test-Administrator {
  [OutputType([bool])]
  param()
  process {
    [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
  }
}

# borrowed from Jeffrey Snover http://blogs.msdn.com/powershell/archive/2006/12/07/resolve-error.aspx
function Resolve-Error-Detailed($ErrorRecord = $Error[0]) {
  $error_message = "========== ErrorRecord:{0}ErrorRecord.InvocationInfo:{1}Exception:{2}"
  $formatted_errorRecord = $ErrorRecord | format-list * -force | out-string
  $formatted_invocationInfo = $ErrorRecord.InvocationInfo | format-list * -force | out-string
  $formatted_exception = ""
  $Exception = $ErrorRecord.Exception
  for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException)) {
    $formatted_exception += ("$i" * 70) + "-----"
    $formatted_exception += $Exception | format-list * -force | out-string
    $formatted_exception += "-----"
  }

  return $error_message -f $formatted_errorRecord, $formatted_invocationInfo, $formatted_exception
}

#Stops Orbit service and related processes
function Stop-Orbit {
  # Stop Service
  Stop-Service -Name "Mobius osquery" -ErrorAction "Continue"
  Start-Sleep -Milliseconds 1000

  # Ensure that no process left running
  Get-Process -Name "orbit" -ErrorAction "SilentlyContinue" | Stop-Process -Force
  Get-Process -Name "osqueryd" -ErrorAction "SilentlyContinue" | Stop-Process -Force
  Get-Process -Name "mobius-desktop" -ErrorAction "SilentlyContinue" | Stop-Process -Force
  Start-Sleep -Milliseconds 1000
}

#Remove Orbit footprint from registry and disk
function Force-Remove-Orbit {
  try {
    #Stoping Orbit
    Stop-Orbit

    #Remove Service
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='Mobius osquery'"
    if ($service) {
      $service.delete() | Out-Null
    }

    #Removing Program files entries
    $targetPath = $Env:Programfiles + "\\Orbit"
    Remove-Item -LiteralPath $targetPath -Force -Recurse -ErrorAction "Continue"

    #Remove HKLM registry entries
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -Recurse  -ErrorAction "SilentlyContinue" |  Where-Object { ($_.ValueCount -gt 0) } | ForEach-Object {
      # Filter for osquery entries
      $properties = Get-ItemProperty $_.PSPath  -ErrorAction "SilentlyContinue" |  Where-Object { ($_.DisplayName -eq "Mobius osquery") }
      if ($properties) {
        #Remove Registry Entries
        $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + $_.PSChildName
        Get-Item $regKey -ErrorAction "SilentlyContinue" | Remove-Item -Force -ErrorAction "SilentlyContinue"
        return
      }
    }
    
    # Write success log
    "Mobiusd successfully removed at $(Get-Date)" | Out-File -Append -FilePath "$env:TEMP\mobius_remove_log.txt"
  }
  catch {
    Write-Host "There was a problem running Force-Remove-Orbit"
    Write-Host "$(Resolve-Error-Detailed)"
    # Write error log
    "Error removing mobiusdaemon at $(Get-Date): $($Error[0])" | Out-File -Append -FilePath "$env:TEMP\mobius_remove_log.txt"
    return $false
  }

  return $true
}

function Main {
  try {
    # Is Administrator check
    if (-not (Test-Administrator)) {
      Write-Host "Please run this script with admin privileges."
      Exit -1
    }

    Write-Host "About to uninstall mobiusdaemon..."

    if ($args[0] -eq "remove") {
      # "remove" is received as argument to the script when called as the
      # sub-process that will actually remove the mobius agent.

      # Log the start of removal process
      "Starting removal process at $(Get-Date)" | Out-File -Append -FilePath "$env:TEMP\mobius_remove_log.txt"
      
      # sleep to give time to mobiusdaemon to send the script results to Mobius
      Start-Sleep -Seconds 20
      
      if (Force-Remove-Orbit) {
        Write-Host "mobiusdaemon was uninstalled."
        Exit 0
      }
      else {
        Write-Host "There was a problem uninstalling mobiusdaemon."
        Exit -1
      }
    }
    else {
      # when this script is executed from mobiusdaemon, it does not immediately
      # remove the agent. Instead, it starts a new detached process that
      # will do the actual removal.
      
      Write-Host "Removing mobiusdaemon, system will be unenrolled in 20 seconds..."
      Write-Host "Executing detached child process"
      
      $execName = $MyInvocation.ScriptName
      $proc = Start-Process -PassThru -FilePath "powershell" -WindowStyle Hidden -ArgumentList "-MTA", "-ExecutionPolicy", "Bypass", "-File", "$execName remove"
      
      # Log the process ID
      "Started removal process with ID: $($proc.Id) at $(Get-Date)" | Out-File -Append -FilePath "$env:TEMP\mobius_remove_log.txt"
      
      Start-Sleep -Seconds 5 # give time to process to start running
      Write-Host "Removal process started: $($proc.Id)."
    }
  }
  catch {
    Write-Host "Error: Entry point"
    Write-Host "$(Resolve-Error-Detailed)"
    Exit -1
  }
}

# Execute the script with arguments passed to it
Main $args[0]
