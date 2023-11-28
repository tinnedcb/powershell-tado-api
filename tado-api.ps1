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
function Get-TadoSessionToken {
    param([switch] $Force)
    if (!$script:TadoAuth -or $Force) {
        $Credentials = Get-TadoCredentials
        $headers = @{"Content-Type" = "application/x-www-form-urlencoded" }
        $clientSecret = "wZaRN7rpjn3FoNyF5IFuxg9uMzYJcvOoQ8QWiIqS3hfk6gLhVlG57j5YNoZL2Rtc"
        $body = "client_id=tado-web-app&grant_type=password&scope=home.user&username=$($Credentials.UserName)&password=$($Credentials.GetNetworkCredential().Password)&client_secret=$clientSecret"
        Write-Host "Getting Tado Session Authentication token... " -NoNewline
        $script:TadoAuth = Invoke-RestMethod 'https://auth.tado.com/oauth/token' -Method 'POST' -Headers $headers -Body $body
    
        if ($script:TadoAuth) {
            Write-Host "Complete"
        }
        else {
            throw "Faild to get Tado Authentication token. Please call Get-TadoSessionToken with your Tado credentials."
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
        "Authorization" = "Bearer $((Get-TadoSessionToken).access_token)"
    }
    Write-Host "Calling $uri"
    Invoke-RestMethod -Uri $uri -Headers $headers
}

function Export-TadoData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime] $FromDate,
        [datetime] $ToDate = (Get-Date),
        [string] $FilePath
    )
    if (!$FromDate) {
        $FromDate = Get-Date -Year $ToDate.Year -Month $ToDate.Month -Day 1
    }
    if (!$FilePath) {
        $FilePath = "tado-zones-" + (Get-Date $ToDate -Format "yyyy-MM-dd") + ".json"
    }
    $token = Get-TadoSessionToken -Force
    Write-Host "Getting User details"
    $userDetails = Get-TadoApiCall "me"
    $homeId = $userDetails.homes.id
    Write-Host "Getting Zones"
    $zones = Get-TadoApiCall "homes/$homeid/zones"
    $date = $FromDate
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
        for ($date = $FromDate; $date -le $ToDate; $date = $date.AddDays(1)) {
            $dateString = Get-Date $date -Format "yyyy-MM-dd"
            $measurements = Get-TadoApiCall "homes/$homeId/zones/$($zone.id)/dayReport?date:$dateString"
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
    $results | ConvertTo-Json -Depth 99 -Compress | Out-File $FilePath -Encoding utf8
    $results
}