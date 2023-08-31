If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Write-Host "I am not responsible for anything. Also I am not reliable for anything. You take full responsibility When running this script."
	Write-Host "By going forward with is script/program . You agree with the terms and conditions."
	sleep 16
# Create a new SpVoice objects
$voice = New-Object -ComObject Sapi.spvoice

# Set the speed - positive numbers are faster, negative numbers, slower
$voice.rate = 0
$voice.speak("You need to get the file path of where the 0.0.2-Debloater is to do this. Hold Shift Right-Click the 0.0.2-Debloater .Slect copy as path...On Windows 11 Hold Shift+F10 then Right-Click the 0.0.2-Debloater")
    Exit
}

Set-ExecutionPolicy Unrestricted -Scope CurrentUser
#$voice = New-Object -ComObject Sapi.spvoice
#!$voice.speek("Do you want to check for a update?")
#!$Ask = (Read-Host "Do you want to check for a update? y=YES n=no")
#!mkdir "C:\Debloter-Temp"
#!cd C:\Debloter-Temp
#!if ( $Ask -ieq 'y') {
#!$file = 'C:\Debloter-Temp\0.0.3-Debloater.ps1'

#!If the file does not exist, create it.
#!if (-not(Test-Path -Path $file -PathType Leaf)) {
#!     try {
#!     #Check for new release
#!         [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
#!         Invoke-WebRequest -MaximumRedirection 2 -Uri 'https://github.com/Activekingdom/Windows-10-Telemetry-and-bloatware/releases/download/0.0.3/0.0.3-Debloater.ps1' -OutFile '0.0.3-Debloater.ps1'
#!         cls
#!         Write-Host "The file [$file] has been created."
#!         Write-Host "Let this script continue working It will remove the old script."
#!         $removeScript = "$SourceFileInitial"
#!     }
#!     catch {
#!         throw $_.Exception.Message
#!     }
#! }
# If the file already exists, show the message and do nothing.
#! else {
#!     Write-Host "Cannot create [$file] because a file with that name already exists."
#! }
#!




$Ask = "null"

#Verify hash
# Create a new SpVoice objects
$voice = New-Object -ComObject Sapi.spvoice

# Set the speed - positive numbers are faster, negative numbers, slower
$voice.rate = 0
cls
$voice.speak("I am not responsible for anything Also I am not reliable for anything You take full responsibility When running this script By going forward with is script slash program You agree with the terms and conditions")
Write-Host "I am not responsible for anything. Also I am not reliable for anything. You take full responsibility When running this script." -ForegroundColor Red
Write-Host "By going forward with is script/program . You agree with the terms and conditions." -ForegroundColor Green
Write-Host "This version is 0.0.2-Debloater" -ForegroundColor Black -BackgroundColor Red
sleep 2
Write-Host "You need to get the file path of where the 0.0.2-Debloater is to do this. Hold Shift Right-Click the 0.0.2-Debloater .Slect copy as path...On Windows 11 Hold Shift+F10 then Right-Click the 0.0.2-Debloater"
Write-Host ""
Write-Host "It should look somithing like "C:\Users\yourusername\Downloads\0.0.2-Debloter.ps1" "
#$voice.speak("You need to get the file path of where the 0.0.2-Debloater is to do this. Hold Shift Right-Click the 0.0.2-Debloater .Slect copy as path...On Windows 11 Hold Shift+F10 then Right-Click the 0.0.2-Debloater")
$SourceFileInitial = (Read-Host "Enter the file path of the 0.0.2-Debloater")
$SourceFileTweaked = $SourceFileInitial.TrimStart('"').TrimEnd('"')
$SourceFile = $SourceFileTweaked.ToString()
cls
 $Algorithmselector = 'X'
    while($Algorithmselector -ne ''){
        Clear-Host
        Write-Host "`n`t`t Algorithm Selector`n"
	Write-Host "Enter The Algorithm From The Website"
        Write-Host -ForegroundColor Cyan "Algorithm Choice's"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow " sha1 Not Allowed or Recommended"

        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " sha256"

        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " sha384"

        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " sha512"

        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow " md5 Not Allowed or Recommended"

        $Algorithmselector = Read-Host "`nSelect A Number: (leave blank to end Selection)"
        # Option 1
        if($Algorithmselector -eq 1){
	    $ChooseAlgorithm = ''
            $ChooseAlgorithm = 'sha1'
            # Pause and wait for input before going back to the menu
	        Write-Host -ForegroundColor red "Warning sha1 has some collisions.This means an attacker can produce two files with the same hash"
           Write-Host -ForegroundColor DarkCyan "SHA1 tryed to be selected but was rejected by Basic security."
           sleep 3
           Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)

        }
        # Option 2
        if($Algorithmselector -eq 2){
	    $ChooseAlgorithm = ''
            $ChooseAlgorithm = 'sha256'
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "SHA256 is selected."
            sleep 2
            break
          #Write-Host "`nPress any key to return to the previous menu"
            #[void][System.Console]::ReadKey($true)
        }

  # Option 3
        if($Algorithmselector -eq 3){
	  $ChooseAlgorithm = ''
            $ChooseAlgorithm = 'sha384'
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "SHA384 is selected."
            sleep 2
            break
         #  Write-Host "`nPress any key to return to the previous menu"
           # [void][System.Console]::ReadKey($true)
        }
  # Option 4
        if($Algorithmselector -eq 4){break}{
	    $ChooseAlgorithm = ''
       	    $ChooseAlgorithm = 'sha512'
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "SHA512 is selected."
            sleep 2
            break
            #Write-Host "`nPress any key to return to the previous menu"
            #[void][System.Console]::ReadKey($true)
        }
  # Option 5
        if($Algorithmselector -eq 5){
	    $ChooseAlgorithm = ''
            $ChooseAlgorithm = 'md5'
 Write-Host -ForegroundColor red "Warning md5 has collisions.This means an attacker can produce two files with the same hash"
           Write-Host -ForegroundColor DarkCyan "`MD5 tryed to be selected but was rejected by Basic security"
            # Pause and wait for input before going back to the menu
           sleep 3
          Write-Host "`nPress any key to return to the previous menu"
           [void][System.Console]::ReadKey($true)
        }

    }

$SourceHash = (Get-FileHash -Path $SourceFile -Algorithm $ChooseAlgorithm).hash
$ComparisonHash = (Read-Host "Paste in the" $ChooseAlgorithm "from the website.")
$ComparisonHash = $ComparisonHash -replace '\s',''
Compare-Object -ReferenceObject $SourceHash -DifferenceObject $ComparisonHash -IncludeEqual
if ($SourceHash -eq $ComparisonHash){
	sleep 2
	cls
	$voice.speak("This script is not tampered with or edited.")
	Write-Host "They are correct it has not been tampered with" -ForegroundColor green
	
}

#The Hash Check 

#This checks if the File has been tampered with. IT WILL EXIT IF SO. TO DISABLE PUT # ON ALL THE NEXT 10 LINES. SO LINES 36-50#
if ($SourceHash -ne $ComparisonHash) {
cls
$voice.speak("THE HASH IS NOT EQUAL! WARNING THIS MIGHT BE TAMPERED WITH OR EDITED")
	Write-Host "THE HASH IS NOT EQUAL! WARNING THIS MIGHT BE TAMPERED WITH OR EDITED" -ForegroundColor Red
	sleep 4
	$voice.speak("IF YOU TAMPERED WITH IT. YOU MUST DISABLE THE HASH CHECK .")
	Write-Host "IF YOU TAMPERED WITH IT. YOU MUST DISABLE THE HASH CHECK ." -ForegroundColor Red
sleep 15
	exit
	end
}

Clear-Variable PSScriptRoot
Clear-Variable SourceFileInitial
#Ask for clean up#
$Ask = (Read-Host "Do you want to stop windows update temporarly. And delete windows update install file?")
if ( $Ask -eq 'y') {
remove-item 'C:\ProgramData\Microsoft\Event Viewer\*'
stop-service wuauserv
$VolumeCaches = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
foreach($key in $VolumeCaches){
New-ItemProperty -Path "$($key.PSPath)" -Name StateFlags0099 -Value 2 -Type DWORD -Force | Out-Null
Write-host "'$key.PSPath'" }
#Run Disk Cleanup
Start-Process -Wait "$env:SystemRoot\System32\Cleanmgr.exe" -ArgumentList /sagerun:99
foreach($key in $VolumeCaches) {
Write-host "'$key.PSPath'"
Remove-ItemProperty -Path "$($key.PSPath)" -Name StateFlags0099 -Force | Out-Null
}
sleep 6
Write-Host "Done"
} else {
Write-Host "Skipping Windows clean up."
}

clear-variable Ask
$Ask = Read-host "Do you want to install Group Policy Editor?"
if ($Ask -eq 'y') {
Get-ChildItem @(
    "C:\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package*.mum",
    "C:\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package*.mum"
) | ForEach-Object { dism.exe /online /norestart /add-package:"$_" }

} else {
    Write-Host "Skipping Install of Group Policy Editor"
    }



clear-variable Ask
$Ask = Read-Host 'scan for corruption y for yes'
if ($Ask -eq 'y') {
    sfc /scannow
} else {
    Write-Host "Skipping Scan"
    }
clear-variable Ask
Write-Host "Updating Windows Defender"
Update-MpSignature -UpdateSource MicrosoftUpdateServer
$Prefer = Get-MpPreference
$is_Done = $True
$Ask = Read-Host "Do you want to hardden Windows defender? Y or N. If windows defender find malware it could be false positive and you can't restore the file "
if ($Ask -eq 'y'){

#https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps&viewFallbackFrom=win10-ps
Read-Host "Do you want to hardden Windows Defender?"
    if ($Ask2 -eq 'y'){
    #Enable Defender signatures for Potentially Unwanted Applications (PUA)
    powershell.exe -command "Set-MpPreference -PUAProtection enable"

    #Enable Defender periodic scanning
    reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -SignatureScheduleDay Everyday
    Set-MpPreference -CheckForSignaturesBeforeRunningScan true
    Set-MpPreference -CloudBlockLevel 1
    Set-MpPreference -CloudExtendedTimeout 40
    Set-MpPreference -DisableCatchupQuickScan true
    Set-MpPreference -DisableArchiveScanning false
    Set-MpPreference -DisableBehaviorMonitoring false
    Set-MpPreference -DisableDnsOverTcpParsing false
    Set-MpPreference -DisableDnsParsing false
    Set-MpPreference -DisableTlsParsing false
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -DisableInboundConnectionFiltering false
    Set-MpPreference -DisableHttpParsing false
    Set-MpPreference -DisableIOAVProtection false
    Set-MpPreference -DisableRdpParsing false
    Set-MpPreference -DisableRealtimeMonitoring false
    Set-MpPreference -DisableRemovableDriveScanning false
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan false
    Set-MpPreference -DisableScanningNetworkFiles false
    Set-MpPreference -DisableScriptScanning false
    Set-MpPreference -DisableSshParsing false
    Set-MpPreference -EnableDnsSinkhole true
    Set-MpPreference -DisableEmailScanning false
    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -RealTimeScanDirection Both

        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f

        #Set-MpPreference -ScanPurgeItemsAfterDelay 7 #Specifies the number of days to keep items in the scan history folder. After this time, Windows Defender removes the items. If you specify a value of zero, Windows Defender does not remove items. If you do not specify a value, Windows Defender removes items from the scan history folder after the default length of time, which is 15 days.
foreach($ScanRange in -ge 3 -and $TheRange -le 20){
[int]$ScanMax = Read-Host ("The number Specifies the number of days to keep items in the scan history folder Range 3-20 . Default is 15 days.") -asinit

#ask
if ($ScanRange -ge 3 -and $TheRange -le 20) {
Set-MpPreference -ScanPurgeItemsAfterDelay $ScanRange
Write-Host "Was now set to [$ScanRange]"

} else {
  write-host "Enter in a number in 3-20."
    }
}
Clear-varable ScanRange
    #Set-MpPreference -ScanAvgCPULoadFactor $ScanMAX #Specifies the maximum percentage CPU usage for a scan. The acceptable values for this parameter are: integers from 5 through 100, and the value 0, which disables CPU throttling. Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50.
foreach($ScanRange in -ge 15 -and $ScanRange -le 45) {
    [int]$ScanRange = Read-Host ("Default is 50 Enter a number in the range 15-45. For SCAN MAX CPU USAGE.") -asinit
   If ($ScanRange -ge 15 -and $ScanRange -le 45) {
   Set-MpPreference -ScanAvgCPULoadFactor $ScanRange
   } else {
    write-host "Enter in a number in 15-45."
   }
}
Clear-varable ScanRange

   # Set-MpPreference -QuarantinePurgeItemsAfterDelay #Specifies the number of days to keep items in the Quarantine folder. If you specify a value of zero or do not specify a value for this parameter, items stay in the Quarantine folder indefinitely.
foreach($ScanRange in -ge 3 -and $ScanRange -le 30) {
    [int]$ScanRange = Read-Host ("Specifie the number of days to keep items in the Quarantine folder. Range of 3-30.") -asinit
   If ($ScanRange -ge 3 -and $ScanRange -le 30) {
   Set-MpPreference -QuarantinePurgeItemsAfterDelay $ScanRange
   } else {
    write-host "Enter in a number in 3-30."
   }
}
Clear-varable ScanRange

    #Set-MpPreference -LowThreatDefaultAction UserDefined
    #Set-MpPreference -ModerateThreatDefaultAction UserDefined
    #Set-MpPreference -HighThreatDefaultAction  UserDefined
    #Set-MpPreference -UnknownThreatDefaultAction UserDefined

    clear-variable Ask
    clear-varable Ask2
        Read-Host "Do you want disable Exclusions? you will not be able to add any place that is Excluded from a scan"
        if ($Ask -eq 'y'){
        powershell.exe -command "Set-MpPreference -DisableAutoExclusions true"
        clear-variable Ask
        clear-varable Ask2
        } else {
        clear-variable Ask
        clear-varable Ask2
        Write-host "Skiping..."
        }
 Start-Sleep 2
 cls
    clear-variable Ask
    clear-varable Ask2
        Write-Host ""
        Write-Host "Specifies the type of membership in Microsoft Active Protection Service. Microsoft Active Protection Service is an online community that helps you choose how to respond to potential threats. The community also helps prevent the spread of new malicious software. "
        Write-Host ""
        Write-Host "0: Disabled. Send no information to Microsoft. This is the default value."
        Write-Host ""
        Write-Host "1: Basic membership. Send basic information to Microsoft about detected software, including where the software came from, the actions that you apply or that apply automatically, and whether the actions succeeded."
        Write-Host ""
        Write-Host ""
        Write-Host "2: Advanced membership. In addition to basic information, send more information to Microsoft about malicious software, spyware, and potentially unwanted software, including the location of the software, file names, how the software operates, and how it affects your computer."
        Write-Host ""
        Write-Host ""
        Read-Host ("what number 0-2?") -asinit
        if ($Ask -eq '0'){
        Set-MpPreference -MAPSReporting Disabled
        clear-variable Ask
        clear-varable Ask2
        }
        elseif ($Ask -eq '1'){
        Set-MpPreference -MAPSReporting Basic
        }
        elseif ($Ask -eq '2'){
        Set-MpPreference -MAPSReporting Advanced
        } else {
        clear-variable Ask
        clear-varable Ask2
        Write-host "Not a number in range 0-2...So Setting to default"
        Set-MpPreference -MAPSReporting Disabled
        } else {
write-Host ""
}
    }

Write-host "Doing a full scan of the computer... It will take awile to skip hold ctrl + c"
Update-MpSignature 
Start-MpScan -ScanType "FullScan"


} else {
Write-Host "Skipping..."
}


##########
# Privacy Settings
##########
# Disable Telemetry
Write-Host "Soon the script is staring to make big changes. stop the script Control+C Will end it"
sleep 3
Write-Host "Disabling Telemetry..."
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Enable Telemetry
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
Write-Host "The script is now staring.To stop the script Control+C or close it out will end it. Ending it could result in more errors and/or misbehavior."
sleep 10
# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0

If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Enable Wi-Fi Sense
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Enable SmartScreen Filter
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"

# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
IF (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")){
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

}
# Enable Bing Search in Start Menu
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled"

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
IF (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"	
}
IF (!(Test-Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" )) {
	New-Item -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" | Out-Null
}
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force -Name "Status" -Type DWord -Value 0

# Enable Location Tracking
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Enable Feedback
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Enable Advertising ID
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"

# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")){
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

#Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    If (Test-Path $Search) {
        Set-ItemProperty $Search -Force -Name AllowCortana -Value 0 -Verbose
    }

# Enable Cortana
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy"
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"

# Restrict Windows Update P2P only to local network
Write-Host "Restricting Windows Update P2P only to local network..."
#0=off 1=On but local network only 2=On,local network private peering only 3=On local network and Internet 99=simply download mode 100=bypass mode
New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

# Unrestrict Windows Update P2P
# Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode"

# Remove AutoLogger file and restrict directory
Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Unrestrict AutoLogger directory
# $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
# icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Enable and start Diagnostics Tracking Service
# Set-Service "DiagTrack" -StartupType Automatic
# Start-Service "DiagTrack"

##########
# Service Tweaks
##########

# Lower UAC level
# Write-Host "Lowering UAC level..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

# Raise UAC level
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

# Enable sharing mapped drives between users
# Write-Host "Enabling sharing mapped drives between users..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

# Disable sharing mapped drives between users
Write-host "Disabling sharing mapped drives between users"
Remove-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"

# Disable Firewall
# Write-Host "Disabling Firewall..."
# Set-NetFirewallProfile -Profile * -Enabled False

# Enable Firewall
# Set-NetFirewallProfile -Profile * -Enabled True

# Disable Windows Defender
# Write-Host "Disabling Windows Defender..."
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

# Enable Windows Defender
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"

# Disable Windows Update automatic restart
Write-Host "Disabling Windows Update automatic restart...You can enable later"
New-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

# Enable Windows Update automatic restart
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0

# Stop and disable Home Groups services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

# Enable and start Home Groups services
# Set-Service "HomeGroupListener" -StartupType Manual
# Set-Service "HomeGroupProvider" -StartupType Manual
# Start-Service "HomeGroupProvider"

 Disable Remote Assistance
 Write-Host "Disabling Remote Assistance..."
If (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance")) {
	New-Item -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

# Enable Remote Assistance
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1

# Enable Remote Desktop w/o Network Level Authentication
# Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0

# Disable Remote Desktop
If (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Terminal Server")) {
	New-Item -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
If (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")) {
	New-Item -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1

##########
# UI Tweaks
##########

# Disable Action Center
# Write-Host "Disabling Action Center..."
# If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
#	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0

# Enable Action Center
# Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled"

# Disable Lock screen
# Write-Host "Disabling Lock screen..."
# If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
# 	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" | Out-Null
# }
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Enable Lock screen
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen"

# Disable Autoplay
Write-Host "Disabling Autoplay..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

# Enable Autoplay
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0

# Disable Autorun for all drives
# Write-Host "Disabling Autorun for all drives..."
# If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
#	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
#}
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Enable Autorun
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"

# Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..."
Set-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Enable Sticky keys prompt
# Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"

# Hide Search button / box
# Write-Host "Hiding Search Box / Button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Show Search button / box
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode"

# Hide Task View button
# Write-Host "Hiding Task View button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Show Task View button
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton"

# Show small icons in taskbar
# Write-Host "Showing small icons in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1

# Show large icons in taskbar
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons"

# Show titles in taskbar
# Write-Host "Showing titles in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1

# Hide titles in taskbar
Remove-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel"

# Show all tray icons
Write-Host "Showing all tray icons..."
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

# Hide tray icons as needed
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"

# Show known file extensions
Write-Host "Showing known file extensions..."
New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Hide known file extensions
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1

Show hidden files
Write-Host "Showing hidden files..."
Set-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Hide hidden files
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2

# Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Change default Explorer view to "Quick Access"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo"

# Show Computer shortcut on desktop
# Write-Host "Showing Computer shortcut on desktop..."
# If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
#	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# Hide Computer shortcut from desktop
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

# Remove Desktop icon from computer namespace
# Write-Host "Removing Desktop icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue

# Add Desktop icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"

# Remove Documents icon from computer namespace
# Write-Host "Removing Documents icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue

# Add Documents icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"

# Remove Downloads icon from computer namespace
# Write-Host "Removing Downloads icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue

# Add Downloads icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"

# Remove Music icon from computer namespace
# Write-Host "Removing Music icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

# Add Music icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"

# Remove Pictures icon from computer namespace
# Write-Host "Removing Pictures icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue

# Add Pictures icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"

# Remove Videos icon from computer namespace
# Write-Host "Removing Videos icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue

# Add Videos icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"

## Add secondary en-US keyboard
#Write-Host "Adding secondary en-US keyboard..."
#$langs = Get-WinUserLanguageList
#$langs.Add("en-US")
#Set-WinUserLanguageList $langs -Force

# Remove secondary en-US keyboard
# $langs = Get-WinUserLanguageList
# Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force



##########
# Remove unwanted applications
##########
# Disable OneDrive

$Ask = (Read-Host "Do you want to disable One Drive? y=YES n=no")
if ( $Ask -ieq 'y') {
Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}

Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
#   Description:
# This script will remove and disable OneDrive integration.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"

if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Force -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Force -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}

else {
Write-Host "One Drive Skiped..."
    }
}
clear-variable Ask
# Enable OneDrive
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC"

# Uninstall OneDrive (WINDOWS WILL NOT SYSPREP WITHOUT IT!)
# Write-Host "Uninstalling OneDrive..."
# Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
# Start-Sleep -s 3
# Stop-Process -Name explorer -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
# 	Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
# }
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Install OneDrive
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive -NoNewWindow
#---------------------------------------------
Write-Host "PACKAGES_NAMES_NEEDS_UPDATING"
## Reinstall Windows 10's Built-In Apps
## Get-AppxPackage -allusers | foreach {Add-AppxPackage -register "$($_.InstallLocation)\appxmanifest.xml" -DisableDevelopmentMode}

get-appxpackage -allusers *3d* | remove-appxpackage
get-appxpackage -allusers *3dbuilder* | remove-appxpackage
get-appxpackage -allusers *bingfinance* | remove-appxpackage
get-appxpackage -allusers *bingnews* | remove-appxpackage
get-appxpackage -allusers *bingsports* | remove-appxpackage
get-appxpackage -allusers *bingweather* | remove-appxpackage
get-appxpackage -allusers *getstarted* | remove-appxpackage
get-appxpackage -allusers *maps* | remove-appxpackage
get-appxpackage -allusers *messaging* | remove-appxpackage
get-appxpackage -allusers *holographic* | remove-appxpackage
get-appxpackage -allusers *oneconnect* | remove-appxpackage
get-appxpackage -allusers *onenote* | remove-appxpackage
get-appxpackage -allusers *people* | remove-appxpackage
get-appxpackage -allusers *phone* | remove-appxpackage
get-appxpackage -allusers *skypeapp* | remove-appxpackage
get-appxpackage -allusers *solitaire* | remove-appxpackage
get-appxpackage -allusers *soundrecorder* | remove-appxpackage
get-appxpackage -allusers *sticky* | remove-appxpackage
get-appxpackage -allusers *sway* | remove-appxpackage
get-appxpackage -allusers *zune* | remove-appxpackage
get-appxpackage -allusers *zunemusic* | remove-appxpackage
get-appxpackage -allusers *zunevideo* | remove-appxpackage
get-appxpackage -allusers *CandyCrush* | remove-appxpackage
get-appxpackage -allusers *Twitter* | remove-appxpackage
get-appxpackage -allusers *BubbleWitch* | remove-appxpackage

Start-Sleep 3
# Uninstall default Microsoft applications ##PACKAGES_NAMES_NEEDS_UPDATING##
Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage -AllUsers


# Install default Microsoft applications
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.3DBuilder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingFinance").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingNews").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingSports").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingWeather").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Getstarted").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftOfficeHub").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.OneNote").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.People").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.SkypeApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Windows.Photos").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsAlarms").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.windowscommunicationsapps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsMaps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsPhone").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsSoundRecorder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.XboxApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneMusic").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneVideo").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.AppConnector").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ConnectivityStore").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.Sway").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Messaging").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.CommsPhone").InstallLocation)\AppXManifest.xml"
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# Uninstall Windows Media Player (optonal)
#Write-Host "Uninstalling Windows Media Player..."
#dism /online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart

# Install Windows Media Player
# dism /online /Enable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart

# Uninstall Work Folders Client
Write-Host "Uninstalling Work Folders Client..."
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

# Install Work Folders Client
# dism /online /Enable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

# Set Photo Viewer as default for bmp, gif, jpg and png
Write-Host "Setting Photo Viewer as default for bmp, gif, jpg, png and tif..."
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
	New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
	New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
	Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
	Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

# Remove or reset default open action for bmp, gif, jpg and png
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse
# Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
# Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse
# Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse

# Show Photo Viewer in "Open with..."
Write-Host "Showing Photo Viewer in `"Open with...`""
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

# Remove Photo Viewer from "Open with..."
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse

# This script disables unwanted Windows services. If you do not want to disable
# certain services comment out the corresponding lines below.

$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    "RemoteRegistry"                           # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    # "WbioSrvc"                               # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                 # WLAN AutoConfig
    "lmhosts"                                  #TCP/IP NetBIOS Helper
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    #"wscsvc"                                  # Windows Security Center Service
    "WSearch"                                 # Windows Search
	"lltdsvc"								 #Link-Layer Topology Discovery Mapper
	"SEMgrSvc"									#Payments and NFC/SE Manager
    #"ndu"                                      # Windows Network Data Usage Monitor ##dose not work.
    #"spoolsv"				       #Print Spooler needed for printing
    # Services which cannot be disabled
    #"WdNisSvc"
)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
	Get-Service -Name $service | Stop-Service -Force
    Get-Service -Name $service | Set-Service -StartupType Disabled
}
####This might cause problems###
Write-Host "DEBUG"
#   Description:
# This script optimizes Windows updates by disabling automatic download and
# seeding updates to other computers.
#
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Disable automatic download and installation of Windows updates"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Disable seeding of updates to other computers via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

#echo "Disabling automatic driver update"
#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value


Write-Output "Disable 'Updates are available' message"

takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"


# This script removes unwanted Apps that come with Windows. If you  do not want
# to remove certain Apps comment out the corresponding lines below.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "PACKAGES_NAMES_NEEDS_UPDATING"
Start-Sleep 3
Write-Output "Uninstalling default apps" 
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
#     "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
#     "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
#     "Microsoft.MixedReality.Portal"
#     "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
#     "Microsoft.Wallet"
    #"Microsoft.Windows.Photos"
#     "Microsoft.WindowsAlarms"
    # "Microsoft.WindowsCalculator"
    # "Microsoft.WindowsCamera"
#     "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"   # can't be re-installed
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
#     "Microsoft.Windows.CloudExperienceHost"
#     "Microsoft.Windows.ContentDeliveryManager"
#     "Microsoft.Windows.PeopleExperienceHost"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
#     "Microsoft.ConnectivityStore"
#     "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"

    # Creators Update apps
    "Microsoft.Microsoft3DViewer"
    #"Microsoft.MSPaint"

    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"

    # Redstone 5 apps
#     "Microsoft.MixedReality.Portal"
    "Microsoft.ScreenSketch"
    "Microsoft.YourPhone"

    # non-Microsoft
    "*PicsArt-PhotoStudio*"
    "*EclipseManager*"
    "*Netflix*"
    "*PolarrPhotoEditorAcademicEdition*"
    "*Wunderlist*"
    "*LinkedInforWindows*"
    "*AutodeskSketchBook*"
    "*Twitter*"
    "*DisneyMagicKingdoms*"
    "*MarchofEmpires*"
    "*ActiproSoftwareLLC*" # next one is for the Code Writer from Actipro Software LLC
    "*Plex*"
    "*iHeartRadio*"
    "*FarmVille*"
    "*Duolingo*"
    "*CyberLinkMediaSuiteEssentials*"
    "DolbyLaboratories.DolbyAccess*"
    "Drawboard.DrawboardPDF"
    "*Facebook*"
    "*Fitbit*"
    "*Flipboard*"
    "*Asphalt8Airborne*"
    "*KeeperSecurityInc*"
    "*COOKINGFEVER*"
    "*PandoraMediaInc*"
    "*CaesarsSlotsFreeCasino*"
    "*ShazamEntertainmentLtd*"
    "*SlingTV*"
    "*SpotifyMusic*"
    "*TheNewYorkTimes*"
    "*ThumbmunkeysLtd*"
    "*TuneIn*"
    "WinZipComputing.WinZipUniversal"
    "*XINGAG*"
    "*RoyalRevolt*"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "*.*.CandyCrushSaga"
    "*.*.CandyCrushSodaSaga"

    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Windows.ContactSupport"

    # apps which other apps depend on
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}
Write-Output "PACKAGES_MIGHT_NEED_UPDATING"
Write-host "DEBUG WINDOWS STORE PreInstalledAppsEverEnabled and PreInstalledAppsEnabled might be problems "
Start-Sleep 3
# Prevents Apps from re-installing ##PACKAGES_NAMES_MIGHT_NEED_UPDATING##
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null	
}
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force "DisableWindowsConsumerFeatures" 1

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue

Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 2

# Prevents SYSPREP from freezing at "Getting Ready" on first boot                          #
# NOTE, DMWAPPUSHSERVICE is a Keyboard and Ink telemetry service, and potential keylogger. #
# It is recommended to disable this service in new builds, but SYSPREP will freeze/fail    #
# if the service is not running. If SYSPREP will be used, add a FirstBootCommand to your   #
# build to disable the service.                                                            #

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"
# Add the line below to FirstBootCommand in answer file #
# reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "disabledmwappushservice" /t REG_SZ /d "sc config dmwappushservice start= disabled"


# Disable Privacy Settings Experience #
# Also disables all settings in Privacy Experience #

reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f




# Set Windows to Dark Mode #

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f

Start-Sleep -s 2
Get-AppxPackage "Microsoft.AsyncTextService" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftEdgeDevToolsClient" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.CallingShellApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.ParentalControls" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Search" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftEdge.Stable" | Remove-AppxPackage

Write-Host "Now Disabling LLMNR"
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v " EnableMulticast" /t REG_DWORD /d "0" /f
netsh firewall>set multicastbroadcastresponse mode=disable profile=all
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type DWORD -Value 0
}
Set-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type DWord -Value 0

#Enable netbios over TCP/IP and DHCP
#Get-WmiObject Win32_NetworkAdapterConfiguration | Where IPAddress
#$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where Description -like "*Ethernet*"
#$adapter.SetTcpIPNetbios(0) | Select ReturnValue
#$adapters=(gwmi win32_networkadapterconfiguration )
#Foreach ($adapter in $adapters){
#Write-Host $adapter
#$adapter.settcpipnetbios(0)
#}
#$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
#Get-ChildItem $key |
#foreach { 
#Set-ItemProperty "$key\$($_.pschildname)" -force -Name "NetbiosOptions" -Value 0
#}
#Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\NetBIOS" -Force -name "Start" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT" -Force -name "Start" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force -name "EnableLMHOSTS" -Type DWord -Value 1
#Disable netbios over TCP/IP and DHCP#
Get-WmiObject Win32_NetworkAdapterConfiguration | Where IPAddress
$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where Description -like "*Ethernet*"
$adapter.SetTcpIPNetbios(2) | Select ReturnValue
$adapters=(gwmi win32_networkadapterconfiguration )
Foreach ($adapter in $adapters){
Write-Host $adapter
$adapter.settcpipnetbios(2)
}
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null
}
#Disable cmd set to 1 in the next line.Default is 0
New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Type DWord -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Force | Out-Null
}
Write-Host "For added security change the value to 0"
Write-host "This will disable powershell from running scripts. It is disable by default"
sleep 3
#The next line will disable powershell script. Set to 0 to disallow scripts.#
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Type DWord -Value 1

Write-Host "Hardening Account Control..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
#BY Default ENABLED EnableSecureUIAPaths Only elevate UIAccess applications that are installed in secure locations... I would not change value unless you know what you are doing
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Type DWord -Value 1

#BY Default ENABLED EnableVirtualization Virtualize file and registry write failures to per-user locations... I would not change value unless you know what you are doing
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Type DWord -Value 1
#Require Password For elevated privileges
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWORD -Value 3
}
Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWORD -Value 3

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWORD -Value 0
}
Set-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWORD -Value 0

Write-Host "Trying To Setting Visual Effects..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null	
}
New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0

Write-Host "BY Default DISABLED Only elevate executables that are signed and validated...Enable for more Securty"
Start-Sleep 3
# Remove the # in the next line to enable "Only elevate executables that are signed and validated"
#New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 1

$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $key |
foreach { 
Set-ItemProperty "$key\$($_.pschildname)" -force -Name "NetbiosOptions" -Value 2
}
Set-ItemProperty -Force -Path "HKLM:\SYSTEM\ControlSet001\Services\NetBIOS" -name "Start" -Type DWord -Value 0
Set-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT" -name "Start" -Type DWord -Value 0
Set-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -name "EnableLMHOSTS" -Type DWord -Value 0
cd C:\Users\All Users\
rm -f '.\Microsoft OneDrive\'
write-Output "Mozilla firefox policies addons"
If (!(Test-Path "HKLM:\Software\Policies\Mozilla\Firefox")) {
	New-Item -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Force | Out-Null
}
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "BlockAboutConfig" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "BlockAboutAddons" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "BlockAboutProfiles" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "BlockAboutSupport" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableSetDesktopBackground" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableFeedbackCommands" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableFirefoxAccounts" -Type DWord -Value 0
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableFirefoxScreenshots" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableFirefoxStudies" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisablePasswordReveal" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisablePocket" -Type DWord -Value 1
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWord -Value 1
Write-Host "Disabling Memory Dumps"
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl")) {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AlwaysKeepMemoryDump" -Type DWORD -Value 0
}
New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AlwaysKeepMemoryDump" -Type DWORD -Value 0

# Remove Password Age Limit (Passwords never expire) #
#net accounts /minpwage:0
#net accounts /maxpwage:0
#net account /minpwlen:8
# Set Password Age Limit to 60 Days#
Write-Output "Now looking at Net Accounts..."
net accounts
Start-Sleep 3
net accounts /minpwage:60
net accounts /maxpwage:120
net accounts /uniquepw:5
net accounts /minpwlen:8
net accounts /forcelogoff:15
Write-Host "This link tells you about Account lock out meaning when too many password attemps have been made."
Write-host "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"
Write-Host "https://docs.microsoft.com/en-us/services-hub/health/remediation-steps-ad/set-the-account-lockout-threshold-to-the-recommended-value"
Start-Sleep 3
net accounts /lockoutwindow:10
net accounts /lockoutDuration:10
##the next line Default is 100. Setting to bigger number would help prvent DOS Attack##
net accounts /lockoutThreshold:25 #The nember could be Bigger or smaller 25-999 should Be a good range.#
Write-host "Net Accounts Now Changed"
net accounts
Start-Sleep 3
#disable internet explorer
Disable-WindowsOptionalFeature -online -FeatureName internet-explorer-optional-amd64 -NoRestart

clear-variable Ask
$Ask = Read-host "Do you need to fix the window store?? Only do this if you can't get the Windows Store working after restart."
if ($Ask -eq 'y') {
cd $home
cd Downloads
wget -o windowsstorefix.zip https://github.com/kkkgo/LTSB-Add-MicrosoftStore/archive/refs/heads/master.zip
Expand-Archive -Path windowsstorefix.zip -DestinationPath $home\Downloads
rm -force windowsstorefix.zip
cd windowsstorefix
cd LTSB-Add-MicrosoftStore-master
.\Add-Store.cmd
sleep 30
} else {
    Write-Host "Skipping..."
  }
#Add hash checking
Clear-Variable SourceFileInitial
Clear-Variable SourceFileTweaked
Clear-Variable SourceFile
Clear-Variable SourceHash
Clear-Variable ComparisonHash
Clear-Variable filedownloadedone
cd $HOME\Downloads\
wget -o HashCheckSetup-v2.4.0.null https://github.com/gurnec/HashCheck/releases/download/v2.4.0/HashCheckSetup-v2.4.0.exe
$SourceFileInitial = "$home\Downloads\HashCheckSetup-v2.4.0.null"
$SourceFileTweaked = $SourceFileInitial.TrimStart('"').TrimEnd('"')
$SourceFile = $SourceFileTweaked.ToString()
$SourceHash = (Get-FileHash -Path $SourceFile -Algorithm SHA384).Hash
#The original file Hash
$ComparisonHash = "485B0C8055AE8A8065B2584BAF81B98201DB5CA30059EAC20E431FB3F5B0EB004F55FE16FB54845E29CE93B4FE63BF27"
#Compare original file with file that is untempered with
if ($SourceHash -ne $ComparisonHash) {
rm -Force HashCheckSetup-v2.4.0.null
$voice.speak("The file might not have been Download or")
$voice.speak("when trying download the needed file the file did not match the original code so the file was deleted for your protection")
	Write-Host "The HASH did not match so deleted for your protection" -ForegroundColor Red
	sleep 4
} else {
Write-Host "First File's Hash Has Matched"
Rename-Item .\HashCheckSetup-v2.4.0.null .\HashCheckSetup-v2.4.0.exe
./HashCheckSetup-v2.4.0.exe
 }

#Download uppin apps from Gethub
cd $home\Downloads\
#Download the file
wget -o clean-start-tiles.zip https://github.com/JollyWizard/clean-start-tiles/archive/refs/tags/0.1.0.zip

#clear all Variables for this check
Clear-Variable SourceFileInitial
Clear-Variable SourceFileTweaked
Clear-Variable SourceFile
Clear-Variable SourceHash
Clear-Variable ComparisonHash
Clear-Variable filedownloadedone
#Getting Hash check for clean-start-tiles.zip
$SourceFileInitial = "$home\Downloads\clean-start-tiles.zip"
$SourceFileTweaked = $SourceFileInitial.TrimStart('"').TrimEnd('"')
$SourceFile = $SourceFileTweaked.ToString()
$SourceHash = (Get-FileHash -Path $SourceFile -Algorithm SHA384).Hash
#The original file Hash
$ComparisonHash = "52AC87D570C2B53A0CA261A0916EF0EA307F6EB9E0D3A0627F69A649E09BD2BB57C5358B96F27CFE9D0F73155B187271"
#Compare original file with file that is untempered with
if ($SourceHash -ne $ComparisonHash) {
rm -force clean-start-tiles.zip
$voice.speak("The file might not have been Download or")
$voice.speak("when trying download the needed file the file did not match the original code so the file was deleted for your protection")
	Write-Host "The HASH did not match so deleted for your protection" -ForegroundColor Red
	sleep 4
} else {
Write-Host "First File's Hash Has Matched"
Expand-Archive -Path clean-start-tiles.zip -DestinationPath $home\Downloads
rm -force clean-start-tiles.zip
cd clean-start-tiles-0.1.0
.\clean-start-tiles.ps1
    }

$list = (Get-StartApps).Name; 
@($list).Count

foreach ($item in $list) {
    Pin-App $item -unpin
}

write-host "IN BATA ADD A SECURE GUEST ACCOUNT. Disable by default. un coment the next  lines... Delete the number sign"
Start-Sleep 3
#net user Secure_Visit /add /active:no
#net user Secure_Visit *
#net localgroup users Secure_Visit /delete
#net localgroup Guests Secure_Visit /add
#net user Secure_Visit /active:yes
#icacls cmd.exe /deny Secure_Visit:RX
#Go to user path
#cd "$env:UserProfile\Downloads"
#mv C:\Debloter-Temp\0.0.3-Debloater.ps1 "$env:UserProfile\Downloads"
#rm C:\Debloter-Temp -Force
#rm $removeScript -Force
##########
# Restart
##########
#Write-Host
Write-Host "you need to restart your system for all settings to take effect" -ForegroundColor Black -BackgroundColor Red
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Output "Sleeping 6 seconds"
clear-history
([Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory())
Set-ExecutionPolicy Restricted -Scope CurrentUser
Start-Sleep -Seconds 6
Restart-Computer
