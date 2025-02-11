# Add at the start of the script
$logPath = "C:\INTUNE_TEST"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}
$logFile = Join-Path $logPath "RegionalSettings_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Output $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

# Check for admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    Exit 1
}

# Define expected values for Latvian
$expectedCulture = "lv-LV"
$expectedNonUnicode = "0426" # 0426 is the code for Latvian

function Set-RegionalSettings {
    param (
        [string]$regPath
    )
    
    # Set GeoID and HomeLocation
    Set-ItemProperty $regPath -Name "GeoID" -Value 140  # Latvia's GeoID
    
    # Also set the Windows home location
    Set-WinHomeLocation -GeoId 140
    
    # Current user format settings
    Set-ItemProperty $regPath -Name "LocaleName" -Value $expectedCulture
    Set-ItemProperty $regPath -Name "sCountry" -Value "Latvia"
    Set-ItemProperty $regPath -Name "sLanguage" -Value "LVI"

    # Number format settings (Latvian defaults)
    Set-ItemProperty $regPath -Name "iDigits" -Value "2"           # Decimal digits
    Set-ItemProperty $regPath -Name "sDecimal" -Value ","         # Decimal symbol
    Set-ItemProperty $regPath -Name "sThousand" -Value " "        # Digit grouping symbol
    Set-ItemProperty $regPath -Name "iNegNumber" -Value "1"       # Negative number format (-1.1)
    Set-ItemProperty $regPath -Name "NumShape" -Value "1"         # Use native digits: Never
    Set-ItemProperty $regPath -Name "iMeasure" -Value "0"         # Metric
    Set-ItemProperty $regPath -Name "sList" -Value ";"            # List separator
    Set-ItemProperty $regPath -Name "sNativeDigits" -Value "0123456789" # Standard digits
    
    # Date format settings
    Set-ItemProperty $regPath -Name "sShortDate" -Value "dd.MM.yyyy"
    Set-ItemProperty $regPath -Name "sLongDate" -Value "dddd, yyyy. 'gada' d. MMMM"
    Set-ItemProperty $regPath -Name "sYearMonth" -Value "yyyy. 'g.' MMMM"  # Added Latvian year-month format
    
    # Time format settings
    Set-ItemProperty $regPath -Name "sTimeFormat" -Value "HH:mm:ss"
    Set-ItemProperty $regPath -Name "sShortTime" -Value "HH:mm"
    Set-ItemProperty $regPath -Name "iFirstDayOfWeek" -Value "0"    # Monday = 0
    Set-ItemProperty $regPath -Name "s1159" -Value ""              # AM symbol (empty for 24h)
    Set-ItemProperty $regPath -Name "s2359" -Value ""              # PM symbol (empty for 24h)
    Set-ItemProperty $regPath -Name "iTime" -Value "1"             # 1 = 24-hour format
    Set-ItemProperty $regPath -Name "iTLZero" -Value "1"           # 1 = leading zeros in time

    # Currency settings
    Set-ItemProperty $regPath -Name "sCurrency" -Value ([char]0x20AC)  # Unicode for Euro symbol
    Set-ItemProperty $regPath -Name "iCurrDigits" -Value "2"
    Set-ItemProperty $regPath -Name "iCurrency" -Value "3"         # Currency positive format
    Set-ItemProperty $regPath -Name "iNegCurr" -Value "8"          # Currency negative format

    # Additional settings that Windows Reset sets
    $userSettingsPath = Join-Path (Split-Path $regPath) "Geo\Nation"
    if (-not (Test-Path $userSettingsPath)) {
        New-Item -Path $userSettingsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $userSettingsPath -Name "Nation" -Value "Latvia" -Type String
    Set-ItemProperty -Path $userSettingsPath -Name "Name" -Value "Latvia" -Type String
    
    # Calendar settings
    $calendarPath = Join-Path (Split-Path $regPath) "Calendars"
    if (-not (Test-Path $calendarPath)) {
        New-Item -Path $calendarPath -Force | Out-Null
    }

    # Set TwoDigitYearMax
    $twoDigitPath = Join-Path $calendarPath "TwoDigitYearMax"
    if (-not (Test-Path $twoDigitPath)) {
        New-Item -Path $twoDigitPath -Force | Out-Null
    }
    Set-ItemProperty -Path $twoDigitPath -Name "1930" -Value "2029" -Type String
    Set-ItemProperty -Path $twoDigitPath -Name "iFirstDayOfWeek" -Value "0" -Type String

    # Set Gregorian calendar settings
    $gregorianPath = Join-Path $calendarPath "Gregorian"
    if (-not (Test-Path $gregorianPath)) {
        New-Item -Path $gregorianPath -Force | Out-Null
    }
    Set-ItemProperty -Path $gregorianPath -Name "iFirstDayOfWeek" -Value "0" -Type String
}

function Test-UserProfileInUse {
    param([string]$sid)
    $explorerProcesses = Get-WmiObject Win32_Process -Filter "name = 'explorer.exe'" | 
        Where-Object { $_.GetOwner().User -eq $sid }
    return $null -ne $explorerProcesses
}

function Update-LoggedInUserSettings {
    param([string]$sid)
    
    try {
        # Get the username from SID
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $username = $objUser.Value.Split('\')[1]
        
        # Create a scheduled task to run as the user
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-WindowStyle Hidden -Command & {
            Set-Culture $using:expectedCulture
            `$regPath = 'HKCU:\Control Panel\International'
            Set-ItemProperty -Path `$regPath -Name 'LocaleName' -Value '$expectedCulture'
            Set-ItemProperty -Path `$regPath -Name 'sCountry' -Value 'Latvia'
            Set-ItemProperty -Path `$regPath -Name 'sLanguage' -Value 'LVI'
            Set-ItemProperty -Path `$regPath -Name 'sDecimal' -Value ','
            Set-ItemProperty -Path `$regPath -Name 'sThousand' -Value ' '
            Set-ItemProperty -Path `$regPath -Name 'sShortDate' -Value 'dd.MM.yyyy'
            Set-ItemProperty -Path `$regPath -Name 'sTimeFormat' -Value 'HH:mm:ss'
            Set-ItemProperty -Path `$regPath -Name 'iFirstDayOfWeek' -Value '0'
            Set-ItemProperty -Path `$regPath -Name 'sCurrency' -Value ([char]0x20AC)
            

            
            # Create and set Geo\Nation settings
            New-Item -Path 'HKCU:\Control Panel\International\Geo\Nation' -Force | Out-Null
            Set-ItemProperty -Path 'HKCU:\Control Panel\International\Geo\Nation' -Name 'Nation' -Value 'Latvia'
            Set-ItemProperty -Path 'HKCU:\Control Panel\International\Geo\Nation' -Name 'Name' -Value 'Latvia'
            
            # Create and set Calendar settings
            New-Item -Path 'HKCU:\Control Panel\International\Calendars' -Force | Out-Null
            New-Item -Path 'HKCU:\Control Panel\International\Calendars\TwoDigitYearMax' -Force | Out-Null
            New-Item -Path 'HKCU:\Control Panel\International\Calendars\Gregorian' -Force | Out-Null
            
            # GeoID
            Set-WinHomeLocation -GeoId 140
            
            Set-ItemProperty -Path 'HKCU:\Control Panel\International\Calendars\TwoDigitYearMax' -Name '1930' -Value '2029'
            Set-ItemProperty -Path 'HKCU:\Control Panel\International\Calendars\TwoDigitYearMax' -Name 'iFirstDayOfWeek' -Value '0'
            Set-ItemProperty -Path 'HKCU:\Control Panel\International\Calendars\Gregorian' -Name 'iFirstDayOfWeek' -Value '0'
        }"
        
        $principal = New-ScheduledTaskPrincipal -UserId $username -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Principal $principal
        
        # Register and start the task
        Register-ScheduledTask -TaskName "UpdateRegionalSettings_$username" -InputObject $task -Force | Start-ScheduledTask
        
        # Wait for task to complete
        Start-Sleep -Seconds 5
        
        # Clean up
        Unregister-ScheduledTask -TaskName "UpdateRegionalSettings_$username" -Confirm:$false
        
        Write-Output "Successfully updated settings for logged-in user $username"
        return $true
    }
    catch {
        Write-Warning "Failed to update settings for logged-in user: $_"
        return $false
    }
}

function Install-LanguagePack {
    try {
        Write-Output "Checking Latvian language pack..."
        
        # Check if Latvian language is installed using registry
        $languagePackPath = "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\lv-LV"
        if (Test-Path $languagePackPath) {
            Write-Output "Latvian language pack is already installed"
            return $true
        }

        Write-Output "Latvian language pack not found. Installing..."
        
        try {
            # Try using DISM to add the language pack
            & dism /online /add-package /packagepath:"C:\Windows\servicing\Microsoft-Windows-Client-Language-Pack_x64_lv-lv.cab" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Successfully installed Latvian language pack using DISM"
                return $true
            }
        } catch {
            Write-Warning "DISM installation failed: $_"
        }

        try {
            # Alternative method using PowerShell
            Install-Language lv-LV -ErrorAction Stop
            Write-Output "Successfully installed Latvian language pack using Install-Language"
            return $true
        } catch {
            Write-Warning "PowerShell installation failed: $_"
            return $false
        }
    }
    catch {
        Write-Warning "Failed to install Latvian language pack: $_"
        return $false
    }
}

try {
    Write-Log "=== Starting Remediation Process ==="
    
    # Force specific language settings using registry
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\Settings" -Name "UILanguage" -Value $expectedCulture
    Set-WinSystemLocale -SystemLocale $expectedCulture
    
    # Install Latvian language pack first
    if (-not (Install-LanguagePack)) {
        Write-Warning "Proceeding with regional settings despite language pack installation issues"
    }
    
    # Set System Locale (Regional Format) to Latvian - HKLM
    Write-Log "`nAttempting to set HKLM System Locale to $expectedCulture..."
    $oldCulture = (Get-WinSystemLocale).Name
    Set-WinSystemLocale -SystemLocale $expectedCulture
    Write-Log "HKLM System Locale changed from $oldCulture to $expectedCulture"

    # Set Language for non-Unicode programs - HKLM
    Write-Log "`nAttempting to set HKLM non-Unicode language to $expectedNonUnicode..."
    $oldNonUnicode = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "Default").Default
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "Default" -Value $expectedNonUnicode
    Write-Log "HKLM non-Unicode language changed from $oldNonUnicode to $expectedNonUnicode"

    # Set Default User settings first
    Write-Log "`n=== Setting Default User Profile Settings ==="
    $defaultUserPath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
    if (Test-Path $defaultUserPath) {
        reg load "HKU\DefaultUser" $defaultUserPath
        Set-RegionalSettings -regPath "Registry::HKEY_USERS\DefaultUser\Control Panel\International"
        [gc]::Collect()
        Start-Sleep -Seconds 1
        reg unload "HKU\DefaultUser"
        Write-Output "Successfully configured Default User profile"
    }
    
    # Get user-specific settings - HKCU
    Write-Log "`n=== Processing User Profiles ==="

    $userProfiles = @()

    # Use CimInstance for more reliable profile detection
    $profiles = Get-CimInstance -ClassName Win32_UserProfile | 
        Where-Object { 
            $_.Special -eq $false -and 
            $_.LocalPath -notlike '*defaultuser*' -and
            $_.LocalPath -notlike '*systemprofile*'
        }

    foreach ($profile in $profiles) {
        Write-Log "Found profile: $($profile.LocalPath) with SID: $($profile.SID)"
        try {
            $profilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($profile.SID)"
            if (Test-Path $profilePath) {
                $userProfiles += Get-Item $profilePath
                Write-Log "Added profile to process list"
            }
        } catch {
            Write-Log "Error adding profile: $_"
        }
    }

    Write-Log "Final profile count: $($userProfiles.Count)"
    foreach ($profile in $userProfiles) {
        $sid = Split-Path $profile.Name -Leaf
        $path = (Get-ItemProperty $profile.PSPath).ProfileImagePath
        Write-Log "Will process: SID=$sid, Path=$path"
    }

    # Process each profile
    foreach ($profile in $userProfiles) {
        $sid = Split-Path $profile.Name -Leaf
        $userPath = (Get-ItemProperty $profile.PSPath).ProfileImagePath
        Write-Log "`nProcessing user profile: $userPath (SID: $sid)"
        
        # Skip system profiles
        if ($userPath -like "*systemprofile" -or $userPath -like "*ServiceProfile*") {
            Write-Log "Skipping system profile"
            continue
        }
        
        # Check if profile is in use
        if (Test-UserProfileInUse $sid) {
            Write-Log "Profile is currently in use - updating via scheduled task..."
            if (Update-LoggedInUserSettings -sid $sid) {
                Write-Log "Successfully updated settings for logged-in user"
            } else {
                Write-Warning "Failed to update settings for logged-in user"
            }
            continue
        }
        
        # Load profile if not already loaded
        $loaded = $false
        if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
            Write-Log "Profile not loaded - attempting to load NTUSER.DAT..."
            $ntUserDat = Join-Path $userPath "NTUSER.DAT"
            if (Test-Path $ntUserDat) {
                reg load "HKU\$sid" $ntUserDat
                $loaded = $true
                Write-Log "Successfully loaded user profile"
            }
        } else {
            Write-Log "Profile already loaded in registry"
        }

        # Apply settings
        if (Test-Path "Registry::HKEY_USERS\$sid\Control Panel\International") {
            Write-Log "Setting multiple regional settings for user..."
            Set-RegionalSettings -regPath "Registry::HKEY_USERS\$sid\Control Panel\International"
            Write-Log "Successfully set all regional settings for user"
        }

        # Unload profile if we loaded it
        if ($loaded) {
            Write-Log "Unloading user profile..."
            [gc]::Collect()
            Start-Sleep -Seconds 1
            reg unload "HKU\$sid"
            Write-Log "Successfully unloaded user profile"
        }
    }

    # Create a flag to indicate system needs restart
    $RestartRequired = $true
    
    Write-Log "`n=== Remediation Complete ==="
    Write-Log "Successfully updated system and user regional settings to Latvian"
    
    if ($RestartRequired) {
        Write-Warning "A system restart is required for the changes to take effect"
    }
    
    # Add this after setting the system locale
    Write-Log "Setting Welcome screen date/time format..."

    try {
        # The Welcome screen uses the System account's settings
        $systemProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18"
        if (Test-Path $systemProfilePath) {
            $systemPath = (Get-ItemProperty $systemProfilePath).ProfileImagePath
            $systemNTUserPath = Join-Path $systemPath "NTUSER.DAT"
            
            if (Test-Path $systemNTUserPath) {
                Write-Log "Loading System profile to set Welcome screen format..."
                reg load "HKU\SystemProfile" $systemNTUserPath
                
                try {
                    Set-RegionalSettings -regPath "Registry::HKEY_USERS\SystemProfile\Control Panel\International"
                    Write-Log "Successfully set Welcome screen format"
                } finally {
                    [gc]::Collect()
                    Start-Sleep -Seconds 1
                    reg unload "HKU\SystemProfile"
                }
            }
        }

        # Also set the system's MUI settings as documented
        $muiPath = "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\Settings"
        if (-not (Test-Path $muiPath)) {
            New-Item -Path $muiPath -Force | Out-Null
        }
        Set-ItemProperty -Path $muiPath -Name "PreferredUILanguages" -Value @($expectedCulture) -Type MultiString

        Write-Log "Successfully configured Welcome screen settings"
    } catch {
        Write-Warning "Failed to set Welcome screen format: $_"
    }
    
    # Add after setting the system locale
    Write-Log "Setting system Country/Region to Latvia..."
    try {
        # Set GeoID in multiple required locations
        $geoLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\International\User Profile",  # New user template
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\International\User Profile\System", # System default
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\International" # Global setting
        )

        foreach ($geoPath in $geoLocations) {
            if (-not (Test-Path $geoPath)) {
                New-Item -Path $geoPath -Force | Out-Null
            }
            Set-ItemProperty -Path $geoPath -Name "GeoID" -Value 140 -Type DWord
        }

        Write-Log "Successfully set system Country/Region to Latvia"
    } catch {
        Write-Warning "Failed to set system Country/Region: $_"
    }
    
    Exit 0
} catch {
    Write-Error "Failed to update regional settings to Latvian: $_"
    Exit 1
} 