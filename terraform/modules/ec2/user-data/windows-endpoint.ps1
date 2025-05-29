# Windows Endpoint Setup Script with Wazuh Agent
# PowerShell script for Windows Server 2019

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

# Create log file
$LogPath = "C:\SOC-Lab-Setup.log"
function Write-Log {
    param([string]$Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Output $Message
}

Write-Log "Starting Windows endpoint setup..."

# Install Chocolatey
Write-Log "Installing Chocolatey..."
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install essential tools
Write-Log "Installing essential tools..."
choco install -y git
choco install -y notepadplusplus
choco install -y 7zip
choco install -y firefox
choco install -y sysinternals

# Enable Windows features
Write-Log "Enabling Windows features..."
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging -All

# Configure Windows Firewall to allow Wazuh communication
Write-Log "Configuring Windows Firewall..."
New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Inbound -Protocol TCP -LocalPort 1514-1516 -Action Allow
New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985-5986 -Action Allow

# Enable PowerShell logging
Write-Log "Enabling PowerShell logging..."
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force
}
Set-ItemProperty -Path $RegPath -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path $RegPath -Name "ModuleNames" -Value "*"

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force
}
Set-ItemProperty -Path $RegPath -Name "EnableScriptBlockLogging" -Value 1

# Enable Windows Event Logging
Write-Log "Configuring Windows Event Logging..."
wevtutil sl Security /ms:1073741824
wevtutil sl System /ms:1073741824
wevtutil sl Application /ms:1073741824
wevtutil sl "Windows PowerShell" /e:true /ms:1073741824
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true /ms:1073741824

# Configure audit policies
Write-Log "Configuring audit policies..."
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Wait for Wazuh server to be ready
Write-Log "Waiting for Wazuh server to be ready..."
Start-Sleep -Seconds 180

# Download and install Wazuh Agent
Write-Log "Installing Wazuh Agent..."
$WazuhServerIP = "${wazuh_server_ip}"
$WazuhInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"
$WazuhInstaller = "C:\temp\wazuh-agent.msi"

if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp"
}

Write-Log "Downloading Wazuh agent from $WazuhInstallerUrl"
Invoke-WebRequest -Uri $WazuhInstallerUrl -OutFile $WazuhInstaller

# Install Wazuh Agent
Write-Log "Installing Wazuh agent with server IP: $WazuhServerIP"
$Arguments = @(
    "/i", $WazuhInstaller,
    "/q",
    "WAZUH_MANAGER=$WazuhServerIP",
    "WAZUH_REGISTRATION_SERVER=$WazuhServerIP",
    "WAZUH_AGENT_GROUP=windows"
)
Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait

# Start Wazuh service
Write-Log "Starting Wazuh service..."
Start-Service -Name "WazuhSvc"
Set-Service -Name "WazuhSvc" -StartupType Automatic

# Install vulnerable applications for testing
Write-Log "Installing vulnerable applications..."

# Install XAMPP for web server testing
choco install -y xampp-80

# Create test web application with vulnerabilities
$WebRoot = "C:\xampp\htdocs"
if (Test-Path $WebRoot) {
    $TestApp = "$WebRoot\vulnerable-app"
    if (!(Test-Path $TestApp)) {
        New-Item -ItemType Directory -Path $TestApp
    }
    
    # Create a simple vulnerable PHP application
    $VulnCode = @'
<?php
// Simple vulnerable application for testing
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>";
    system($cmd);  // Command injection vulnerability
    echo "</pre>";
}

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // SQL injection vulnerability (simulated)
    echo "<p>Login attempt: " . $username . "/" . $password . "</p>";
    
    if ($username == "admin" && $password == "password") {
        echo "<p style='color: green;'>Login successful!</p>";
    } else {
        echo "<p style='color: red;'>Login failed!</p>";
    }
}
?>

<html>
<head><title>Vulnerable Test App</title></head>
<body>
<h1>SOC Lab - Vulnerable Test Application</h1>
<h2>Command Execution (for testing)</h2>
<form method="GET">
    Command: <input type="text" name="cmd" placeholder="dir" />
    <input type="submit" value="Execute" />
</form>

<h2>Login Form</h2>
<form method="POST">
    Username: <input type="text" name="username" /><br/><br/>
    Password: <input type="password" name="password" /><br/><br/>
    <input type="submit" value="Login" />
</form>

<p><em>Hint: Try admin/password</em></p>
</body>
</html>
'@
    
    $VulnCode | Out-File -FilePath "$TestApp\index.php" -Encoding UTF8
}

# Create scheduled task to generate test events
Write-Log "Creating scheduled task for test event generation..."
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -Command `"Get-EventLog -LogName Security -Newest 1 | Out-Null; Write-EventLog -LogName Application -Source 'SOC-Lab' -EventId 1001 -Message 'Test event generated' -EntryType Information`""
$TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 15)
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "SOC-Lab-TestEvents" -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Description "Generate test events for SOC lab"

# Create test users for attack scenarios
Write-Log "Creating test users..."
$TestUsers = @("testuser1", "testuser2", "serviceaccount")
foreach ($User in $TestUsers) {
    try {
        New-LocalUser -Name $User -Password (ConvertTo-SecureString "TempPass123!" -AsPlainText -Force) -Description "Test user for SOC lab" -AccountNeverExpires
        Add-LocalGroupMember -Group "Users" -Member $User
        Write-Log "Created user: $User"
    } catch {
        Write-Log "User $User may already exist: $($_.Exception.Message)"
    }
}

# Configure Windows Defender (but allow for testing)
Write-Log "Configuring Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false

# Add exclusion for test directory
Add-MpPreference -ExclusionPath "C:\temp\test-malware"

# Create test directories
Write-Log "Creating test directories..."
$TestDirs = @("C:\temp\test-malware", "C:\temp\uploads", "C:\inetpub\logs")
foreach ($Dir in $TestDirs) {
    if (!(Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force
    }
}

# Enable RDP
Write-Log "Enabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0

# Configure PowerShell remoting
Write-Log "Configuring PowerShell remoting..."
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-WSManQuickConfig -Force

# Create info file
$InfoContent = @"
SOC Lab Windows Endpoint Setup Complete
======================================

This Windows Server 2019 instance has been configured with:

✓ Wazuh Agent (connected to: ${wazuh_server_ip})
✓ IIS Web Server with vulnerable test application
✓ XAMPP with PHP support
✓ Enhanced Windows logging and auditing
✓ PowerShell script block logging
✓ Test user accounts for attack scenarios
✓ Remote Desktop enabled
✓ PowerShell remoting enabled

Vulnerable Applications:
- Test PHP app: http://localhost/vulnerable-app/
- XAMPP control panel: http://localhost/

Test Accounts:
- testuser1 / TempPass123!
- testuser2 / TempPass123!
- serviceaccount / TempPass123!

Logs Location:
- Setup log: C:\SOC-Lab-Setup.log
- Windows Event Logs: Event Viewer
- IIS Logs: C:\inetpub\logs\LogFiles

For security testing purposes only!
"@

$InfoContent | Out-File -FilePath "C:\SOC-Lab-Info.txt" -Encoding UTF8

Write-Log "Windows endpoint setup completed successfully!"
Write-Log "Wazuh agent should now be communicating with server at: ${wazuh_server_ip}"
Write-Log "Vulnerable applications are available for testing"

# Final restart to ensure all services start properly
Write-Log "Scheduling restart in 2 minutes to complete setup..."
shutdown /r /t 120 /c "SOC Lab setup complete - restarting to finalize configuration"