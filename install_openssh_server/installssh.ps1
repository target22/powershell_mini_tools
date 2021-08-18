
# Define variables
$hostName=hostname
$logFile="\\172.16.10.4\ssh$\installopenssh.log.txt"
$windowsVersion=([system.environment]::osversion.version | select-object Major | ForEach-Object {$_.Major})
$windowsBuild=([system.environment]::osversion.version | select-object Build | ForEach-Object {$_.Build})
#$PathSetup="C:\Program Files\openssh64bit\install-sshd.ps1"
    # Not necessary because it is not possible

Write-Output "----------------INSTALL OPENSSH FOR $hostName --------------------------"

# Check Windows's version and build before installing
    # Check version before install
if ($windowsVersion -eq 10)
    {
    if ($windowsBuild -ge 18090)
        {
        # Check OpenSSH exist?
        if ((Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*' | select-object State | ForEach-Object {$_.State}) -eq "Installed")
            {
            $InS1=Write-Output "[successful] The OpenSSH-Server was installed on $hostName!"
            $InS1
                Add-Content $logFile -value $InS1
            }
        else
            {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
                $InS2=Write-Output  "[successful] The OpenSSH-Server successfuly installed  $hostName!"
                $InS2
                    Add-Content $logFile -value $InS2
            }
        #CONFIG 
            #open firewall (port 22) & startup service automatic
            if ((Get-NetFirewallRule -Name *ssh* | Select-Object Name | ForEach-Object {$_.Name} ) -eq "sshd") 
                {
                Write-Host  "[successful] The SSHD service was opened on $hostName!"
                Set-Service -Name sshd -StartupType 'Automatic' 
                Set-Service -Name ssh-agent -StartupType 'Automatic'
                    Write-Host  "[successful] The SSHd Service set automatic"
                    Write-Host  "[successful] The SSHd Service set automatic"
                Start-Service sshd
                    Write-Output  "[successful] start-service sshd"
                Start-service ssh-agent
                New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
                }
                
            else
                {
                New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
                    Write-Host  "[successful] The SSHd Service was opened"
                Set-Service -Name sshd -StartupType 'Automatic' 
                Set-Service -Name ssh-agent -StartupType 'Automatic'
                    Write-Host  "[successful] The SSHd Service set automatic"
                    Write-Host  "[successful] The SSHd Service set automatic"
                Start-Service sshd
                    Write-Output  "[successful] start-service sshd"
                Start-service ssh-agent
                New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
                }
        }
                
    else
        {
        powershell -executionpolicy bypass -file $PathSetup
        Set-Service -Name sshd -StartupType 'Automatic' 
        Set-Service -Name ssh-agent -StartupType 'Automatic'
            Write-Host  "[successful] The SSHd Service set automatic"
        Start-Service sshd
            Write-Output  "[successful] start-service sshd"
        Start-service ssh-agent
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        }
    }
else
    {
    Copy-Item  -Path '\\172.16.10.4\ssh$\openssh64bit' -Destination 'C:\Program Files' -Recurse -Force
    powershell -executionpolicy bypass -file $PathSetup
    Set-Service -Name sshd -StartupType 'Automatic' 
    Set-Service -Name ssh-agent -StartupType 'Automatic'
        Write-Host  "[successful] The SSHd Service set automatic"
    Start-Service sshd
        Write-Output  "[successful] start-service sshd"
    Start-service ssh-agent
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    }

