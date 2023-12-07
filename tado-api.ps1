function Set-CredentialsToFile {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
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
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Read the JSON content from the file
    $jsonContent = Get-Content -Path $FilePath | Out-String | ConvertFrom-Json

    # Convert the secure password string back to a secure string
    $securePassword = ConvertTo-SecureString $jsonContent.Password

    # Create a PSCredential object using the stored properties
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $jsonContent.Username, $securePassword

    return $credentials
}
function Get-TadoCredentials {
    Param(
        [PSCredential] $Credentials, 
        [switch] $SaveCredsToFile
    )
    $filePath = Join-Path $env:USERPROFILE ".TadoApiCreds.json"
    
    if (!$Credentials) {
        if (Test-Path $filePath) {
            $Credentials = Get-CredentialsFromFile -FilePath $filePath
        }
        else {
            $Credentials = (Get-Credential -Message "Enter your Tado credentials")
        }
    }
    if ($SaveCredsToFile) {
        Write-Host "Saving encrypted credentials to file"
        Set-CredentialsToFile -Credential $Credentials -FilePath $filePath
    }
    $Credentials
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
    Write-Host "Calling $uri"
    Invoke-RestMethod -Uri $uri -Headers $headers
}
function Export-TadoMonthDataToFile{
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime] $FromDate,
        [datetime] $ToDate = (Get-Date),
        [string] $FilePath
    )
    $ToDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day $ToDate.Day
    
    # Read existing files to check for missing months
    # going back to the earliest date

    if (!$FromDate) {
        $FromDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day 1
    }
    $token = Get-TadoAuthToken -Force
    Write-Host "Getting User details"
    $userDetails = Get-TadoApiCall "me"
    $homeId = $userDetails.homes.id
    Write-Host "Getting Zones"
    $zones = Get-TadoApiCall "homes/$homeid/zones"
    
    $earliestDate = ($zones.dateCreated | get-date | Measure-Object -Minimum).Minimum
    $earliestMonthStart = Get-Date -Year $earliestDate.Year -Month $earliestDate.Month -Day 1
    Write-Host "Earliest Zone date = " (Get-Date $ToDate -Format "yyyy-MM-dd")
    $lastFilepath = $null
    for ($date = $earliestMonthStart; $date -le $ToDate; $date = $date.AddMonths(1)){   
            $filepath = "tado-zones-"+(Get-Date $date -Format "yyyy-MM") + ".json"
            Write-Host "Checking for file $filepath" -NoNewline
            $getMonth = $false
            if (Test-Path $filepath) {
                Write-Host " ... Found"
                if ($ToDate -lt $date.AddMonths(1)) {
                    $getMonth = $true
                }
            }
            elseif($lastFilepath){
                Write-Host " ... not found, and last file is $lastFilepath"
            }
            else{
                Write-Host " ... not found."
                $getMonth = $true
            }
            if ($getMonth) {
                $lastDay = $date.AddMonths(1).AddDays(-1)
                if ($lastDay -gt $ToDate) {
                    $lastDay = $ToDate
                }
                Write-Host "Getting month data for $date to $lastDay"
                Export-TadoData -FromDate $date -ToDate $lastDay
            }
            $lastFilepath = $filepath
    }

}

function Export-TadoData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime] $FromDate,
        [datetime] $ToDate = (Get-Date),
        [string] $FilePath
    )
    $ToDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day $ToDate.Day
    if (!$FromDate) {
        $FromDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day 1
    }
    if (!$FilePath) {
        $FilePath = "tado-zones-" + (Get-Date $ToDate -Format "yyyy-MM") + ".json"
    }
    $token = Get-TadoAuthToken -Force
    Write-Host "Getting User details"
    $userDetails = Get-TadoApiCall "me"
    $homeId = $userDetails.homes.id
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
    Write-Host "Writing data to $FilePath"
    $results | ConvertTo-Json -Depth 99 -Compress | Out-File $FilePath -Encoding utf8
    $results
}