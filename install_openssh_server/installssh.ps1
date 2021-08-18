
# Define variables
$hostName=hostname
$logFile="\\172.16.10.4\ssh$\installopenssh.log.txt"
$windowsVersion=([system.environment]::osversion.version | select-object Major | ForEach-Object {$_.Major})
$windowsBuild=([system.environment]::osversion.version | select-object Build | ForEach-Object {$_.Build})

#$PathSetup="C:\Program Files\openssh64bit\install-sshd.ps1"
    # Not necessary because it is not possible

Write-Output "----------------INSTALL OPENSSH FOR $hostName ----------------"

# Check the Windows version and build before installing
    # Check the version before installing
if (($windowsVersion -eq 10) -and ($windowsBuild -ge 18090))
{
    # Check exist of the OpenSSH before installing
    # Get-WindowsCapability: Setting > "Apps & features" > "Optional features" 

    # If OpenSSH.Server has existed
    if ((Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | ForEach-Object State) -eq "Installed")
    {
        $logMessage = Write-Output "[successful] OpenSSH was existed on $hostName!"
        $logMessage
        Add-Content $logFile -value $logMessage
    }
    # If not exists
    else 
    {
        # Check "Windows Update" service is running?
        # If not running
        if (-not (Get-Service -Name 'wuauserv' | ForEach-Object Status) -eq "Running") 
        {
            # Start service the "Windows Updates" before installing (if not, it fails)
            Set-Service -Name 'wuauserv' -StartupType 'Manual' -Status 'Running'

            # Install
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        }
        # If "Windows Update" service is running
        else 
        {
            # Install
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        }

        # Check OpenSSH.Server has existed to be sure installed
        if ((Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | ForEach-Object State) -eq "Installed")
        {
            $logMessage = Write-Output  "[successful] The OpenSSH-Server successful installed on $hostName!"
            $logMessage
            Add-Content $logFile -value $logMessage
        }
        # If fails, display messages and break the script
        else
        {
            $logMessage = Write-Output  "[failed] The OpenSSH-Server fail installed!"
            $logMessage
            Add-Content $logFile -value $logMessage
            return
        }
    }

    # Configuration: Firewall, DefaultShell, Set-Service Automatic, ...
    # Check FirewallRule has existed?
    # If has existed
    if ((Get-NetFirewallRule -Name *ssh* | ForEach-Object Name).Length -ge 1) 
    # Not correct if compare -eq 'sshd',
    # because, maybe more one result:  OpenSSH-Server-In-TCP, sshd)
    { 
        Write-Host  "FirewallRule has existed and the SSHd port was opened"

        # Set service automatic and start Service
        Set-Service -Name sshd -StartupType 'Automatic' -Status 'Running'
        Write-Host  "[successful] The sshd service set automatic & running"

        Set-Service -Name ssh-agent -StartupType 'Automatic' -Status 'Running'
        Write-Host  "[successful] The ssh-agent service set automatic & running"

        # Set service sshd, ssh-agent auto restart when start fail
        sc.exe failure sshd reset= 30 actions= restart/5000
        sc.exe failure ssh-agent reset= 30 actions= restart/5000

        # Set DefaultShell = Powershell
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    } 
    # If not exists
    else
        {
            # Create FirewallRule for Port 22 - SSH
            New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
            Write-Host  "[successful] The SSHd port was opened"

            # Set service automatic and start Service
            Set-Service -Name sshd -StartupType 'Automatic' -Status 'Running'
            Write-Host  "[successful] The sshd service set automatic & running"

            Set-Service -Name ssh-agent -StartupType 'Automatic' -Status 'Running'
            Write-Host  "[successful] The ssh-agent service set automatic & running"

            # Set service sshd, ssh-agent auto restart when start fail
            sc.exe failure sshd reset= 30 actions= restart/5000
            sc.exe failure ssh-agent reset= 30 actions= restart/5000

            # Set DefaultShell = Powershell
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        }

}
else
{
    Write-Host "[failed] Windows is not support instal official OpenSSH"
}

