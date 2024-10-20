# Function to decode the JWT token

# Big thanks to 

function Get-GraphTokens {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [switch]$ExternalCall,

        [Parameter(Position = 1, Mandatory = $False)]
        [String[]]$Client = "MSGraph",

        [Parameter(Position = 2, Mandatory = $False)]
        [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",

        [Parameter(Position = 3, Mandatory = $False)]
        [String]$Resource = "https://graph.microsoft.com",

        [Parameter(Position = 4, Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device = 'Default',

        [Parameter(Position = 5, Mandatory = $False)]
        [String]$Browser = 'Default',

        [Parameter(Position = 6, Mandatory = $False)]
        [String]$ConfigFilePath = "./get-tokenrc.json"
    )

    function Invoke-JwtTokenDecoder {
        Param(
            [Parameter(Mandatory = $True)]
            [String]$AccessToken,
    
            [Parameter(Mandatory = $True)]
            [PSCustomObject]$Config
        )
    
        $claimInfo = $Config.claimInfo
        $dangerousScopes = $Config.dangerousScopes
    
        # Decode the JWT
        $TokenPayload = $AccessToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
        while ($TokenPayload.Length % 4) { $TokenPayload += "=" }
        try {
            $TokenByteArray = [System.Convert]::FromBase64String($TokenPayload)
            $TokenJson = [System.Text.Encoding]::UTF8.GetString($TokenByteArray)
            $TokenObject = $TokenJson | ConvertFrom-Json
        }
        catch {
            Throw "Error decoding JWT token: $_"
        }
    
        # Base date for UNIX timestamp conversion
        $BaseDate = Get-Date -Date "01-01-1970"
    
        # Initialize arrays for table data and risky attributes
        $TableData = @()
        $riskyAttributes = @()
    
        foreach ($key in $TokenObject.PSObject.Properties.Name) {
            $value = $TokenObject.$key
            $claim = $claimInfo.$key
            $displayValue = $value
    
            # Get acronym and category from the centralized hashtable
            if ($claim) {
                $acronym = $claim.acronym
                $category = $claim.category
            } else {
                $acronym = $key  # Use the key as the acronym if not defined
                $category = 'Other'
            }
    
            # Convert UNIX timestamps to human-readable dates
            if ($key -in @('iat', 'nbf', 'exp')) {
                $date = $BaseDate.AddSeconds([double]$value).ToLocalTime()
                $displayValue = "$date"
            }
            elseif ($key -eq 'scp') {
                # Format scopes into a table with categories as rows
                $scopes = $value -split ' '
                $groupedScopes = @{}
    
                foreach ($scope in $scopes) {
                    switch -Regex ($scope) {
                        '^AuditLog'          { $group = 'AuditLog' }
                        '^Calendar'          { $group = 'Calendar' }
                        '^Files'             { $group = 'Files' }
                        '^Directory'         { $group = 'Directory' }
                        '^Group'             { $group = 'Group' }
                        '^Mail'              { $group = 'Mail' }
                        '^People'            { $group = 'People' }
                        '^Print'             { $group = 'Print' }
                        '^Sensitive'         { $group = 'Sensitive' }
                        '^Tasks'             { $group = 'Tasks' }
                        '^Team'              { $group = 'Team' }
                        '^User'              { $group = 'User' }
                        Default              { $group = 'Other' }
                    }
                    if (-not $groupedScopes[$group]) {
                        $groupedScopes[$group] = @()
                    }
                    $groupedScopes[$group] += $scope
    
                    # Check if scope is dangerous
                    if ($dangerousScopes -contains $scope) {
                        if (-not ($riskyAttributes -contains $scope)) {
                            $riskyAttributes += $scope
                        }
                    }
                }
    
                # Build a table of scopes per group
                $ScopeTable = @()
                foreach ($group in $groupedScopes.Keys | Sort-Object) {
                    $scopesInGroup = $groupedScopes[$group] -join ' '
                    $ScopeTable += [PSCustomObject]@{
                        'Group Name' = $group
                        'Values'     = $scopesInGroup
                    }
                }
    
                # Determine the maximum lengths for formatting
                $maxGroupLength = ($ScopeTable | ForEach-Object { $_.'Group Name'.Length } | Measure-Object -Maximum).Maximum
                $maxValuesLength = ($ScopeTable | ForEach-Object { $_.Values.Length } | Measure-Object -Maximum).Maximum
    
                # Build the header
                $headerGroup = 'Group Name'.PadRight($maxGroupLength)
                $headerValues = 'Values'
                $displayValue = "$headerGroup  $headerValues`n"
                $displayValue += ('-' * ($maxGroupLength + $maxValuesLength + 2)) + "`n"
    
                # Build each row
                foreach ($item in $ScopeTable) {
                    Write-Host ""
                    $groupText = $item.'Group Name'.PadRight($maxGroupLength)
                    $valuesText = $item.Values
                    $displayValue += "    $groupText  $valuesText`n"
                }
                $displayValue = $displayValue.TrimEnd()
            }
            elseif ($value -is [System.Array]) {
                # If the value is an array, join it into a string
                $displayValue = ($value -join ', ')
            }
    
            # Ensure displayValue is a string
            $displayValue = [string]$displayValue
    
            # Add a custom object to the array for each property
            $TableData += [PSCustomObject]@{
                Acronym  = $acronym
                Value    = $displayValue
                Category = $category
            }
        }
    
        # Add a row for risky attributes if any exist
        if ($riskyAttributes.Count -gt 0) {
            $riskyValue = ($riskyAttributes | Sort-Object | Get-Unique | Out-String).Trim()
            $TableData += [PSCustomObject]@{
                Acronym  = 'Risky Attributes'
                Value    = "$riskyValue"
                Category = 'Security'
            }
        }
    
        # Sort the table by category, then by acronym
        $TableData = $TableData | Sort-Object Category, Acronym
    
        # Determine the maximum lengths for formatting
        $maxAcronymLength = ($TableData | ForEach-Object { $_.Acronym.Length } | Measure-Object -Maximum).Maximum
        $maxValueLength = ($TableData | ForEach-Object {
            ($_ -split "`n" | Measure-Object Length -Maximum).Maximum
        } | Measure-Object -Maximum).Maximum
    
        # Print table header
        $headerAcronym = 'Acronym'.PadRight($maxAcronymLength)
        $headerValue = 'Value'
        Write-Host "$headerAcronym  $headerValue" -ForegroundColor White
        Write-Host ('-' * ($maxAcronymLength + $maxValueLength + 2))
    
        # Print each entry with the category
        foreach ($item in $TableData) {
            $acronymText = $item.Acronym.PadRight($maxAcronymLength)
            $valueLines = $item.Value -split "`n"
    
            # Determine the color based on the category
            switch ($item.Category) {
                'Token Details'                 { $color = 'Yellow' }
                'User & Authentication Details' { $color = 'Green' }
                'Application & Tenant Details'  { $color = 'Cyan' }
                'Security'                      { $color = 'Red' }
                'Refresh Token'                 { $color = 'Magenta' }
                Default                         { $color = 'White' }
            }
    
            foreach ($line in $valueLines) {
                $valueText = $line
                Write-Host "$acronymText " -ForegroundColor $color -NoNewline
                Write-Host "$valueText"
                # Clear acronym text after the first line to align values
                $acronymText = ' ' * $maxAcronymLength
            }
        }
    
        return $TokenObject
    }
    
    # Function to handle device code authentication
    function Invoke-DeviceCodeAuth {
        Param(
            [String]$ClientID,
            [String]$Resource,
            [PSCustomObject]$Config,
            [String]$Device = 'Default',
            [String]$Browser = 'Default'
        )
    
        $Body = @{
            client_id = $ClientID
            resource  = $Resource
        }
        $Headers = New-AuthHeaders -Config $Config -Device $Device -Browser $Browser
    
        $AuthResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Headers $Headers -Body $Body
    
        Write-Host -ForegroundColor Yellow $AuthResponse.message
    
        $Continue = $true
        while ($Continue) {
            $Body = @{
                client_id  = $ClientID
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                code       = $AuthResponse.device_code
                scope      = "openid"
            }
    
            try {
                $Tokens = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $Body
    
                if ($Tokens) {
                    return $Tokens
                }
            }
            catch {
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $Details = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($Details.error -eq "authorization_pending") {
                        Write-Output $Details.error
                    }
                    else {
                        Write-Host -ForegroundColor Red "An error occurred: $($_.Exception.Message)"
                        $Continue = $false
                    }
                }
                else {
                    Write-Host -ForegroundColor Red "An error occurred: $($_.Exception.Message)"
                    $Continue = $false
                }
            }
    
            if ($Continue) {
                Start-Sleep -Seconds 3
            }
        }
        return $null
    }
    
    # New function to create authentication headers with integration of Invoke-ForgeUserAgent
    function New-AuthHeaders {
        Param(
            [Parameter(Mandatory = $True)]
            [PSCustomObject]$Config,
            [Parameter(Mandatory = $False)]
            [String]$Device = 'Default',
            [Parameter(Mandatory = $False)]
            [String]$Browser = 'Default'
        )
    
        $userAgents = $Config.userAgents
    
        # Get agents for the specified device
        $DeviceAgents = $userAgents.$Device
        if (-not $DeviceAgents) {
            Write-Host -ForegroundColor Yellow "Device '$Device' not found. Using 'Default' device."
            $DeviceAgents = $userAgents.Default
        }
    
        # Get the User-Agent string for the specified browser
        $UserAgentString = $DeviceAgents.$Browser
        if (-not $UserAgentString) {
            Write-Host -ForegroundColor Yellow "Browser '$Browser' not found for device '$Device'. Using 'Default' browser."
            $UserAgentString = $DeviceAgents.Default
        }
    
        if (-not $UserAgentString) {
            Throw "User-Agent for device '$Device' and browser '$Browser' not found in configuration."
        }
    
        return @{
            "Accept"       = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
            "User-Agent"   = $UserAgentString
        }
    }
    
    # MAIN
    # Load the JSON configuration file once
    if (-not (Test-Path -Path $ConfigFilePath)) {
        Throw "Configuration file '$ConfigFilePath' not found."
    }

    $jsonContent = Get-Content -Path $ConfigFilePath -Raw
    try {
        $Config = $jsonContent | ConvertFrom-Json
    }
    catch {
        Throw "Error converting JSON file: $_"
    }
    # Check if tokens already exist
    if ($global:Tokens) {
        do {
            Write-Host -ForegroundColor Cyan "[*] It appears tokens already exist in your `$Tokens variable. Do you want to authenticate again? (Yes/No)"
            $Answer = Read-Host
            $Answer = $Answer.ToLower()
            if ($Answer -eq "yes" -or $Answer -eq "y") {
                Write-Host -ForegroundColor Yellow "[*] Initializing device code authentication..."
                $global:Tokens = $null
                break
            }
            elseif ($Answer -eq "no" -or $Answer -eq "n") {
                Write-Host -ForegroundColor Yellow "[*] Aborting..."
                return
            }
            else {
                Write-Host -ForegroundColor Red "Invalid input. Please enter Yes or No."
            }
        } while ($true)
    }

    # Call the device code authentication function
    $tokens = Invoke-DeviceCodeAuth -ClientID $ClientID -Resource $Resource -Config $Config -Device $Device -Browser $Browser

    # Process the received tokens
    if ($tokens) {
        # Decode the JWT token
        $TokenObject = Invoke-JwtTokenDecoder -AccessToken $tokens.access_token -Config $Config
        $global:tenantid = $TokenObject.tid
        $global:Tenantid = $TokenObject.tid

        # Store tokens globally
        $global:Tokens = $TokenObject.aio
        $global:Tokens = $TokenObject.aio
        # Return tokens if called as an external function
        if ($ExternalCall) {
            return $Tokens
        }
    }
}
