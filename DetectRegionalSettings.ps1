# Get current user's culture and regional settings
$currentCulture = Get-WinSystemLocale
$nonUnicodeLang = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language" -Name "Default" -ErrorAction SilentlyContinue

# Add logging
$logPath = "C:\INTUNE_TEST"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}
$logFile = Join-Path $logPath "RegionalSettings_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Output $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

# Define expected values for Latvian
$expectedCulture = "lv-LV"
$expectedNonUnicode = "0426" # 0426 is the code for Latvian

# Initialize compliance status
$isCompliant = $true
$outputMessage = ""

$checkGeoNation = $false

# Check Default User profile
$defaultUserPath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
if (Test-Path $defaultUserPath) {
    Write-Log "Checking Default User profile..."
    reg load "HKU\DefaultUser" $defaultUserPath
    
    try {
        $defaultRegPath = "Registry::HKEY_USERS\DefaultUser\Control Panel\International"
        
        # Define all settings to check - matching remediation script
        $expectedSettings = @{
            "LocaleName" = $expectedCulture
            "sCountry" = "Latvia"
            "sLanguage" = "LVI"
            "sDecimal" = ","
            "sThousand" = " "
            "sShortDate" = "dd.MM.yyyy"
            "sTimeFormat" = "HH:mm:ss"
            "sShortTime" = "HH:mm"
            "iFirstDayOfWeek" = "0"
            "sCurrency" = [char]0x20AC
            "iCurrDigits" = "2"
            "iCurrency" = "3"
            "iNegCurr" = "8"
            "iTime" = "1"  # 24-hour format
            "iTLZero" = "1"  # Leading zeros in time
            "sYearMonth" = "yyyy. 'g.' MMMM"
            "GeoID" = "140"  # Latvia's GeoID (0x8c)
        }

        foreach ($setting in $expectedSettings.Keys) {
            $currentValue = (Get-ItemProperty -Path $defaultRegPath -Name $setting -ErrorAction SilentlyContinue).$setting
            if ($currentValue -ne $expectedSettings[$setting]) {
                $isCompliant = $false
                $outputMessage += "Default User profile has incorrect $setting. Expected: $($expectedSettings[$setting]), Current: $currentValue`n"
                Write-Log "Default User profile has incorrect $setting. Expected: $($expectedSettings[$setting]), Current: $currentValue"
            }
        }

        # Check Geo\Nation settings
        if ($checkGeoNation) {
            $geoPath = "Registry::HKEY_USERS\DefaultUser\Control Panel\International\Geo\Nation"
            if (Test-Path $geoPath) {
                $geoSettings = @{
                    "Nation" = "Latvia"
                    "Name" = "Latvia"
                }
                foreach ($setting in $geoSettings.Keys) {
                    $currentValue = (Get-ItemProperty -Path $geoPath -Name $setting -ErrorAction SilentlyContinue).$setting
                    if ($currentValue -ne $geoSettings[$setting]) {
                        $isCompliant = $false
                        $outputMessage += "Default User profile has incorrect Geo\Nation $setting`n"
                        Write-Log "Default User profile has incorrect Geo\Nation $setting"
                    }
                }
            } else {
                $isCompliant = $false
                $outputMessage += "Default User profile is missing Geo\Nation settings`n"
                Write-Log "Default User profile is missing Geo\Nation settings"
            }
        }
    } catch {
        Write-Warning "Could not check Default User settings: $_"
        Write-Log "Could not check Default User settings: $_"
    } finally {
        [gc]::Collect()
        Start-Sleep -Seconds 1
        reg unload "HKU\DefaultUser"
    }
}

# Check System Regional Format (HKLM)
if ($currentCulture.Name -ne $expectedCulture) {
    $isCompliant = $false
    $outputMessage += "System locale is not set to Latvian ($expectedCulture). Current: $($currentCulture.Name)`n"
    Write-Log "System locale is not set to Latvian ($expectedCulture). Current: $($currentCulture.Name)"
}

# Check Language for non-Unicode programs (HKLM)
if ($nonUnicodeLang.Default -ne $expectedNonUnicode) {
    $isCompliant = $false
    $outputMessage += "Non-Unicode language is not set to Latvian ($expectedNonUnicode). Current: $($nonUnicodeLang.Default)`n"
    Write-Log "Non-Unicode language is not set to Latvian ($expectedNonUnicode). Current: $($nonUnicodeLang.Default)"
}

# Check current user settings (HKCU, commented out for intune testing)
# 
# $currentUserPath = "HKCU:\Control Panel\International"
# $currentLocale = (Get-ItemProperty $currentUserPath -Name "LocaleName" -ErrorAction SilentlyContinue).LocaleName
# if ($currentLocale -ne $expectedCulture) {
#     $isCompliant = $false
#     $outputMessage += "Current user locale is not set to Latvian. Current: $currentLocale`n"
#     Write-Log "Current user locale is not set to Latvian. Current: $currentLocale"
# }

# Check user-specific settings
Write-Log "Checking User Profiles..."

$userProfiles = @()

# Method 1: Registry ProfileList
$regProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
    Where-Object { $_.Name -match 'S-1-5-21' }
Write-Log "Found $($regProfiles.Count) profiles in registry"
$userProfiles += $regProfiles

# Method 2: CimInstance for additional profile detection
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

# Remove duplicates
$userProfiles = $userProfiles | Select-Object -Unique

Write-Log "Final profile count: $($userProfiles.Count)"
foreach ($profile in $userProfiles) {
    $sid = Split-Path $profile.Name -Leaf
    $userPath = (Get-ItemProperty $profile.PSPath).ProfileImagePath
    Write-Log "Processing: $userPath (SID: $sid)"
    
    # Skip system profiles
    if ($userPath -like "*systemprofile" -or $userPath -like "*ServiceProfile*") {
        Write-Log "Skipping system profile"
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
    }

    if (Test-Path "Registry::HKEY_USERS\$sid\Control Panel\International") {
        $regPath = "Registry::HKEY_USERS\$sid\Control Panel\International"
        
        # Define all settings to check - matching remediation script
        $expectedSettings = @{
            "LocaleName" = $expectedCulture
            "sCountry" = "Latvia"
            "sLanguage" = "LVI"
            "sDecimal" = ","
            "sThousand" = " "
            "sShortDate" = "dd.MM.yyyy"
            "sTimeFormat" = "HH:mm:ss"
            "sShortTime" = "HH:mm"
            "iFirstDayOfWeek" = "0"
            "sCurrency" = [char]0x20AC
            "iCurrDigits" = "2"
            "iCurrency" = "3"
            "iNegCurr" = "8"
            "iTime" = "1"  # 24-hour format
            "iTLZero" = "1"  # Leading zeros in time
            "sYearMonth" = "yyyy. 'g.' MMMM"
            "GeoID" = "140"  # Latvia's GeoID (0x8c)
        }

        foreach ($setting in $expectedSettings.Keys) {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $setting -ErrorAction SilentlyContinue).$setting
            if ($currentValue -ne $expectedSettings[$setting]) {
                $isCompliant = $false
                $outputMessage += "User profile ($userPath) has incorrect $setting. Expected: $($expectedSettings[$setting]), Current: $currentValue`n"
                Write-Log "User profile ($userPath) has incorrect $setting. Expected: $($expectedSettings[$setting]), Current: $currentValue"
            }
        }

        # Check Geo\Nation settings
        if ($checkGeoNation) {
            $geoPath = "Registry::HKEY_USERS\$sid\Control Panel\International\Geo\Nation"
            if (Test-Path $geoPath) {
                $geoSettings = @{
                    "Nation" = "Latvia"
                    "Name" = "Latvia"
                }
                foreach ($setting in $geoSettings.Keys) {
                    $currentValue = (Get-ItemProperty -Path $geoPath -Name $setting -ErrorAction SilentlyContinue).$setting
                    if ($currentValue -ne $geoSettings[$setting]) {
                        $isCompliant = $false
                        $outputMessage += "User profile ($userPath) has incorrect Geo\Nation $setting`n"
                        Write-Log "User profile ($userPath) has incorrect Geo\Nation $setting"
                    }
                }
            } else {
                $isCompliant = $false
                $outputMessage += "User profile ($userPath) is missing Geo\Nation settings`n"
                Write-Log "User profile ($userPath) is missing Geo\Nation settings"
            }
        }
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

# Output results
if ($isCompliant) {
    $message = "Compliant: All system and user settings are set to Latvian"
    Write-Log $message
    Write-Output $message
    Exit 0
} else {
    Write-Log "Non-compliant settings found:"
    Write-Output $outputMessage
    Exit 1
} 