$script:TadoConfigFilepath = Join-Path $env:USERPROFILE ".TadoApiConfig.json"
$script:TadoCredsFilepath = Join-Path $env:USERPROFILE ".TadoApiCreds.json"
function Set-TadoDataDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DataDirectory
    )
    $script:tadoConfig = [PSCustomObject]@{
        DataDirectory = $DataDirectory
    }
    $script:tadoConfig | ConvertTo-Json | Out-File $script:TadoConfigFilepath -Encoding utf8 -Force
}
function Get-TadoDataDirectory {
    if ($script:tadoConfig) {
        $script:tadoConfig.DataDirectory
    }
    elseif (Test-Path $script:TadoConfigFilepath) {
        $script:tadoConfig = Get-Content $script:TadoConfigFilepath | ConvertFrom-Json
        $script:tadoConfig.DataDirectory
    }
    else {
        '.\'
    }
}
function Set-CredentialsToFile {
    param (
        [System.Management.Automation.PSCredential]$Credential,
        [string]$FilePath = $script:TadoCredsFilepath
    )

    # Convert the secure password to a secure string representation
    $securePasswordString = ConvertFrom-SecureString $Credential.Password

    # Create a hashtable to store credential properties
    $credentialProperties = @{
        Username = $Credential.UserName
        Password = $securePasswordString
    }

    # Convert the hashtable to JSON and save it to the file
    $credentialProperties | ConvertTo-Json | Set-Content -Path $FilePath
}

function Get-CredentialsFromFile {
    param (
        [string]$FilePath = $script:TadoCredsFilepath
    )

    # Read the JSON content from the file
    $jsonContent = Get-Content -Path $FilePath | Out-String | ConvertFrom-Json

    # Convert the secure password string back to a secure string
    $securePassword = ConvertTo-SecureString $jsonContent.Password

    # Create a PSCredential object using the stored properties
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $jsonContent.Username, $securePassword

    return $credentials
}
function Set-TadoDefaulCredentials {
    Param(
        [PSCredential] $Credentials = (Get-Credential -Message "Enter your Tado credentials")
    )
    Set-CredentialsToFile -Credential $Credentials -FilePath $script:TadoCredsFilepath
}

function Get-TadoCredentials {
    Param(
        [PSCredential] $Credentials, 
        [switch] $SaveCredsToFile
    )
    if ($Credentials) {
        $script:TadoCredentials = $Credentials
        if ($SaveCredsToFile) {
            Write-Host "Saving encrypted credentials to file"
            Set-CredentialsToFile -Credential $Credentials -FilePath $filePath
        }
    }
    else {
        if (!$script:TadoCredentials -and (Test-Path $script:TadoCredsFilepath)) {
            $script:TadoCredentials = Get-CredentialsFromFile -FilePath $script:TadoCredsFilepath
        }
        else {
            throw "No Tado Credentials found. Either pass these in with -Credentials, or save your Creds with Set-TadoDefaulCredentials"
        }
    }

    $script:TadoCredentials
}
function Get-TadoAuthToken {
    param([switch] $Force)
    if (!$script:TadoAuth -or
        $script:TadoAuth.refreshTime -lt (Get-Date) -or 
        $Force
    ) {
        $Credentials = Get-TadoCredentials
        $headers = @{"Content-Type" = "application/x-www-form-urlencoded" }
        $clientSecret = "wZaRN7rpjn3FoNyF5IFuxg9uMzYJcvOoQ8QWiIqS3hfk6gLhVlG57j5YNoZL2Rtc"
        $body = "client_id=tado-web-app&grant_type=password&scope=home.user&username=$($Credentials.UserName)&password=$($Credentials.GetNetworkCredential().Password)&client_secret=$clientSecret"
        Write-Host "Getting Tado Session Authentication token... " -NoNewline
        $authToken = Invoke-RestMethod 'https://auth.tado.com/oauth/token' -Method 'POST' -Headers $headers -Body $body
        if ($authToken) {
            $script:TadoAuth = $authToken | Add-Member -MemberType NoteProperty -Name "refreshTime" -Value (Get-Date).AddSeconds($authToken.expires_in - 10) -Force -PassThru
            Write-Host "Complete"
        }
        else {
            throw "Failed to get Tado Authentication token. Please call Get-TadoAuthToken with your Tado credentials."
        }
    }
    $script:TadoAuth
}

function Get-TadoApiCall {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path
    )
    $uri = "https://my.tado.com/api/v2/$Path"
    $headers = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $((Get-TadoAuthToken).access_token)"
    }
    Write-Verbose "Calling $uri"
    Invoke-RestMethod -Uri $uri -Headers $headers
}

function Get-TadoHomeId {
    if (!$script:tadoHomeId) {
        Write-Host "Getting User details"
        $userDetails = Get-TadoApiCall "me"
        $script:tadoHomeId = $userDetails.homes.id
    }
    $script:tadoHomeId
}

function Export-TadoZones {
    $homeId = Get-TadoHomeId
    Write-Host "Getting Zones"
    $zones = Get-TadoApiCall "homes/$homeId/zones"   
    $zones | Add-Member -MemberType NoteProperty -Name "active" -Value $true -Force

    # Merge current list of zones, with any older zones that no long exist.
    $filepath = ".\tado-zones.json"
    if (Test-Path $filepath) {
        Write-Host "Reading previous list of Zones from '$filepath'"
        $previousZones = Get-Content $filepath | ConvertFrom-Json
        $existingZoneIds = $zones.id
        $legacyZones = $previousZones | Where-Object { $existingZoneIds -NotContains $_.id } | ForEach-Object { $_.active = $false; $_ }
        if ($legacyZones) {
            $zones += $legacyZones
        }
    }
    $zones | ConvertTo-Json -Depth 99 -Compress | Out-File $filepath -Encoding utf8
    $zones
}

function Export-TadoData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $DataDirectoryPath = (Get-TadoDataDirectory)
    )
    # Update Active Zones
    $zones = Export-TadoZones
    $activeZones = $zones | Where-Object active

    # Search for existing months data
    $months = Get-TadoMonthsToExport -Zones $activeZones -DataDirectoryPath $DataDirectoryPath

    foreach ($month in $months) {
        $monthData = Get-TadoMonthData -Zones $activeZones -DataDirectoryPath $DataDirectoryPath -Date $month
        $filename = Get-TadoMonthFilename -DataDirectoryPath $DataDirectoryPath -Date $month
        Write-Host "Writing data file $filename"
        $monthData | ConvertTo-Json -Depth 99 -Compress | Out-File $filename -Encoding utf8 -Force
    }

}
function Get-TadoMonthFilename {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $DataDirectoryPath = (Get-TadoDataDirectory),
        [datetime] $Date
    )
    Join-Path $DataDirectoryPath ("tado-data-" + (Get-Date $Date -Format "yyyy-MM") + ".json")
}

function Get-TadoMonthData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array] $Zones = (Get-TadoApiCall "homes/$(Get-TadoHomeId)/zones"),
        [string] $DataDirectoryPath = (Get-TadoDataDirectory),
        [datetime] $Date = (Get-Date)
    )
    $filename = Get-TadoMonthFilename -DataDirectoryPath $DataDirectoryPath -Date $Date

    $dayData = @()
    if (Test-Path $filename) {
        $fileData = Get-Content $filename | ConvertFrom-Json

        # Shift the startDate to the last day from the file, so we refetch that days day, onwards.
        $startDate = ($fileData.date | Measure-Object -Maximum).Maximum
        # Add all days before the last day in the file, to the output array
        $dayData += $fileData | Where-Object date -lt $startDate
    }
    else {
        $startDate = Get-Date -Year $Date.Year -Month $Date.Month -Day 1
    }
    # Set endDate to last day of the month
    $endDate = (Get-Date -Year $Date.Year -Month $Date.Month -Day 1).AddMonths(1).AddDays(-1)

    # Check if the endDate is greater than today.
    $now = Get-Date
    if ($now -lt $endDate) {
        $endDate = $now.Date
    }

    Write-Host "Getting month data for $startDate to $endDate"
    $dayData += Get-TadoData -Zones $activeZones -StartDate $startDate -EndDate $endDate

    $dayData
}

function Get-TadoMonthsToExport {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array] $Zones = (Get-TadoApiCall "homes/$(Get-TadoHomeId)/zones"),
        [string] $DataDirectoryPath = (Get-TadoDataDirectory)
    )
    $now = Get-Date
    # Convert current DateTime to midnight today i.e. 00:00:00
    $today = Get-Date -Year $now.Year -Month $now.Month -Day $now.Day
    
    # Find when the oldest zone was created
    $earliestDate = ($Zones.dateCreated | get-date | Measure-Object -Minimum).Minimum
    # Get the 1st of the month for the oldest zone
    $earliestMonthStart = Get-Date -Year $earliestDate.Year -Month $earliestDate.Month -Day 1

    Write-Host "Earliest Zone date = " (Get-Date $earliestDate -Format "yyyy-MM-dd")
    # Walk up each month from the oldest zone create date, to this month,
    # returning the 1st of the month for every month we need to fetch data for.
    for ($date = $earliestMonthStart; $date -le $today; $date = $date.AddMonths(1)) {   
        $filepath = Get-TadoMonthFilename -DataDirectoryPath $DataDirectoryPath -Date $date
        Write-Host "Checking for file $filepath" -NoNewline
        if (Test-Path $filepath) {
            Write-Host " ... Found"
            # If the file is for this months, it will need the latest data adding to it
            if ($today -lt $date.AddMonths(1)) {
                $date
            }
        }
        else {
            $date
        }
    }
}

function Get-TadoData {
    [CmdletBinding()]
    param (
        [array] $Zones = (Get-TadoApiCall "homes/$(Get-TadoHomeId)/zones"),
        [datetime] $StartDate,
        [datetime] $EndDate = (Get-Date).Date
    )
    # Ensure start and end dates are at midnight on the day 00:00:00
    if (!$StartDate) {
        $StartDate = (Get-Date -Year $EndDate.Year -Month $EndDate.Month -Day 1).Date
    }
    else {
        $StartDate = $StartDate.Date
    }
    $EndDate = $EndDate.Date
    
    $homeId = Get-TadoHomeId
    Write-Host "Getting data from $StartDate to $EndData"
    for ($date = $StartDate; $date -le $EndDate; $date = $date.AddDays(1)) {
        $dateString = Get-Date $date -Format "yyyy-MM-dd"
        Write-Host "Getting data for $dateString"
        $zoneData = @()
        foreach ($zone in ($Zones | where id -ne 0)) {

            if ((Get-Date $zone.dateCreated) -lt $date.AddDays(1)) {
                
                Write-Host "Getting data for $dateString - Zone '$($zone.name)'"
            
                $zoneDayReport = Get-TadoApiCall "homes/$homeId/zones/$($zone.id)/dayReport?date=$dateString"
                $zoneDayReport | Add-Member -MemberType NoteProperty -Name "zoneId" -Value $zone.id -Force
                $zoneData += $zoneDayReport
            }
        }
        # Return all zone data for this day
        [PSCustomObject]@{
            date  = Get-Date $date -Format "yyyy-MM-ddT00:00:00.000Z"
            zones = $zoneData
        }
    }
}

function Get-TadoDataLegacy {
    [CmdletBinding()]
    param (
        [array] $Zones = (Get-TadoApiCall "homes/$(Get-TadoHomeId)/zones"),
        [datetime] $FromDate,
        [datetime] $ToDate = (Get-Date)
    )
    $ToDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day $ToDate.Day
    if (!$FromDate) {
        $FromDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day 1
    }
    $homeId = Get-TadoHomeId
    Write-Host "Getting Zones"
    $zones = Get-TadoApiCall "homes/$homeid/zones"
    Write-Host " ... Found $($zones.Length)"
    $results = [PSCustomObject]@{
        zones              = @()
        hotWaterProduction = $null
        weather            = $null
    }
    foreach ($zone in ($zones | where id -ne 0)) {
        $temperatures = @()
        $humidity = @()
        $callForHeat = @()
        $hotWaterProduction = @()
        $weather = @()
        if ((Get-Date $zone.dateCreated) -gt $FromDate) {
            $startDate = Get-Date $zone.dateCreated
        }
        else {
            $startDate = $FromDate
        }
        Write-Host "$($zone.name) from $startDate to $ToDate"
        for ($date = $startDate; $date -le $ToDate; $date = $date.AddDays(1)) {
            $dateString = Get-Date $date -Format "yyyy-MM-dd"
            $measurements = Get-TadoApiCall "homes/$homeId/zones/$($zone.id)/dayReport?date=$dateString"
            $temperatures += $measurements.measuredData.insideTemperature.dataPoints
            $humidity += $measurements.measuredData.humidity.dataPoints
            $callForHeat += $measurements.callForHeat.dataIntervals
            $hotWaterProduction += $measurements.hotWaterProduction.dataIntervals
            $weather += $measurements.weather.condition.dataIntervals
        }
        if (!$results.hotWaterProduction) {
            $results.hotWaterProduction = $hotWaterProduction
        }
        if (!$results.weather) {
            $results.weather = $weather
        }
        $measurements = [PSCustomObject] @{
            temperatures = $temperatures
            humidity     = $humidity
            callForHeat  = $callForHeat 
        }
        $zone | Add-Member -MemberType NoteProperty -Name "measurements" -Value $measurements -Force
        $results.zones += $zone
    }

    $results
}
$script:TimeIntervalMinutes = 5
$script:frostTemperature = 5

function ConvertTo-TadoSimplifiedFile {
    $filenames = Join-Path (Get-TadoDataDirectory) "tado-data-*.json"
    $dataMonths = Get-Item $filenames | Get-Content | ConvertFrom-Json

    $allZoneDayReports = $dataMonths | % { $_ } | where zones | % { $_.zones }

    $targetTemperature = $allZoneDayReports | % {
        $zoneId = $_.zoneId
        $_.stripes.dataIntervals | % {
            $time = Get-Date $_.from
            $time = Get-DateTimeRounded $time
            $toTime = Get-Date $_.to
            $toTime = Get-DateTimeRounded $toTime
            if ($_.value.setting.temperature) {
                $tempValue = $_.value.setting.temperature.celsius
            }
            else {
                $tempValue = $script:frostTemperature
            }
            [pscustomobject]@{
                zoneId    = $zoneId
                timestamp = Get-Date ($time.AddMinutes(1)) -Format 'yyyy-MM-ddThh:mm:ss.000Z'
                value     = $tempValue 
            }
            while ($time -le $toTime) {
                [pscustomobject]@{
                    zoneId    = $zoneId
                    timestamp = Get-Date $time -Format 'yyyy-MM-ddThh:mm:ss.000Z'
                    value     = $tempValue 
                }

                $time = $time.AddMinutes($script:TimeIntervalMinutes)
            }
            
        } 
    }
    $temperatures = $allZoneDayReports | % {
        $zoneId = $_.zoneId
        $_.measuredData.insideTemperature.dataPoints | % { 
            [pscustomobject]@{
                zoneId    = $zoneId
                timestamp = $_.timestamp
                value     = $_.value.celsius 
            } 
        } 
    }
    $humidity = $allZoneDayReports | % {
        $zoneId = $_.zoneId
        $_.measuredData.humidity.dataPoints | % { 
            [pscustomobject]@{
                zoneId    = $zoneId
                timestamp = $_.timestamp
                value     = $_.value 
            } 
        } 
    }
    $filename = Join-Path (Get-TadoDataDirectory) "tado-measurements.json" 
    [PSCustomObject]@{
        temperature       = $temperatures
        humidity          = $humidity
        targetTemperature = $targetTemperature
    } | ConvertTo-Json -Depth 99 -Compress | Out-File $filename -Encoding utf8 -Force

}
function Get-DateTimeRounded {
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime] $dateTime,
        [int] $RoundToMinutes = 15
    )
    $dateTime.AddMinutes(([int]($dateTime.Minute / $RoundToMinutes) * $RoundToMinutes) - $dateTime.Minute).AddSeconds(-$dateTime.Second)
}