#requires -Version 7.2

<#
.SYNOPSIS
Adds Copilot Studio agent owner details to a PPAC consumption report.

.DESCRIPTION
Imports the agent-level Copilot Credits CSV downloaded from Power Platform
admin center and joins each row to the Dataverse bot inventory of every
environment referenced in the report.

The Entra app registration requires these delegated permissions with admin
consent:
- Power Platform API: EnvironmentManagement.Environments.Read
- Dynamics CRM: user_impersonation

Configure the app as a public client ("Allow public client flows" = Yes).
No secret or certificate is required. If "Power Platform API" is not listed
under "APIs my organization uses", create its service principal first
(application ID 8578e004-a5c6-46e7-913e-12f58912df43).

The signed-in user must be able to see each environment in Power Platform
admin center and needs a Dataverse security role with read access to the
Bot, User and Team tables in each environment. Endpoints are public cloud
only (GCC, GCC High and DoD are not supported).

JoinStatus values in the output:
- Matched                      Agent found; available owner details populated.
                               Owner name or contact fields may still be blank.
- EnvironmentNotVisible        Environment not returned for the signed-in user.
- EnvironmentHasNoDataverseUrl Environment has no Dataverse database.
- EnvironmentReadFailed        The Dataverse query failed (see warnings),
                               typically a missing security role or throttling.
- AgentNotFound                Environment read succeeded but no bot with this
                               Agent Id exists (deleted agent, or a consumer that
                               is not a Dataverse bot).

.PARAMETER ClientId
Application (client) ID of the public-client app registration.

.PARAMETER TenantId
Directory (tenant) ID.

.PARAMETER ConsumptionCsvPath
Path to the per-agent Copilot Credits consumption CSV exported from PPAC.

.PARAMETER OutputPath
Destination CSV. Defaults to a timestamped file in the current directory.
Must not point to the input consumption CSV.

.EXAMPLE
.\Export-CopilotStudioConsumptionOwners.ps1 `
    -ClientId '11111111-1111-1111-1111-111111111111' `
    -TenantId '00000000-0000-0000-0000-000000000000' `
    -ConsumptionCsvPath '.\EntitlementConsumptionTenantPerAgentDetailsReport_MCSMessages_30.csv' `
    -OutputPath '.\CopilotConsumptionWithOwners.csv'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid]$ClientId,

    [Parameter(Mandatory)]
    [guid]$TenantId,

    [Parameter(Mandatory)]
    [ValidateScript(
        { Test-Path -LiteralPath $_ -PathType Leaf },
        ErrorMessage = 'Consumption CSV not found: {0}'
    )]
    [string]$ConsumptionCsvPath,

    [string]$OutputPath = (
        Join-Path (Get-Location) (
            'CopilotConsumptionWithOwners-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
        )
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ConsumptionCsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConsumptionCsvPath)
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$pathComparison = if ($IsWindows) {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}
if ([string]::Equals($ConsumptionCsvPath, $OutputPath, $pathComparison)) {
    throw 'OutputPath must differ from ConsumptionCsvPath; the original PPAC report will not be overwritten.'
}

$script:TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$script:DeviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
$script:RefreshToken = $null
$script:TokenCache = @{}

# Bound the number of interactive prompts so a consent problem cannot turn
# into one device-code prompt per environment.
$script:InteractiveSignIns = 0
$script:MaxInteractiveSignIns = 2

# Transient HTTP status codes that are retried with back-off.
$script:TransientStatusCodes = @(429, 502, 503, 504)
$script:MaxRequestAttempts = 5

#region Helpers

function Get-ObjectValue {
    # Strict-mode-safe property read: returns $null when the object or the
    # property does not exist instead of throwing.
    param(
        [AllowNull()][object]$InputObject,
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-NormalizedId {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    return ([string]$Value).Trim().Trim('{', '}').ToLowerInvariant()
}

function Get-OAuthError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $body = Get-ObjectValue $ErrorRecord.ErrorDetails 'Message'
    if (-not $body) {
        return $null
    }

    try {
        return $body | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Get-ErrorSummary {
    # Combines the generic exception text with the service's own error body
    # (for HTTP errors PowerShell puts the response body in ErrorDetails).
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $summary = $ErrorRecord.Exception.Message
    $details = Get-ObjectValue $ErrorRecord.ErrorDetails 'Message'
    if (-not $details) {
        return $summary
    }

    try {
        $parsed = $details | ConvertFrom-Json
        $serviceMessage = Get-ObjectValue (Get-ObjectValue $parsed 'error') 'message'
        if ($serviceMessage) {
            $details = $serviceMessage
        }
    }
    catch {
        # Body is not JSON; keep the raw text.
    }

    if ($details.Length -gt 500) {
        $details = $details.Substring(0, 500) + '...'
    }

    return "$summary $details"
}

#endregion Helpers

#region Authentication

function Request-DeviceCodeToken {
    param([string]$Scope)

    $deviceCode = Invoke-RestMethod -Method Post -Uri $script:DeviceCodeEndpoint -Body @{
        client_id = $ClientId
        scope     = "openid offline_access $Scope"
    } -ContentType 'application/x-www-form-urlencoded'

    Write-Host ''
    Write-Host $deviceCode.message -ForegroundColor Yellow
    Write-Host ''

    $interval = [int]$deviceCode.interval
    if ($interval -lt 1) {
        $interval = 5
    }
    $expiresAt = [datetimeoffset]::UtcNow.AddSeconds([int]$deviceCode.expires_in)

    while ([datetimeoffset]::UtcNow -lt $expiresAt) {
        Start-Sleep -Seconds $interval

        try {
            return Invoke-RestMethod -Method Post -Uri $script:TokenEndpoint -Body @{
                client_id   = $ClientId
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                device_code = $deviceCode.device_code
            } -ContentType 'application/x-www-form-urlencoded'
        }
        catch {
            $oauthError = Get-OAuthError $_
            if (-not $oauthError) {
                throw
            }

            $errorCode = Get-ObjectValue $oauthError 'error'
            if ($errorCode -eq 'authorization_pending') {
                continue
            }
            if ($errorCode -eq 'slow_down') {
                $interval += 5
                continue
            }

            throw "Interactive authentication failed: $errorCode - $(Get-ObjectValue $oauthError 'error_description')"
        }
    }

    throw 'Interactive authentication timed out.'
}

function Get-AccessToken {
    param([string]$ResourceUrl)

    $scope = '{0}/.default' -f $ResourceUrl.TrimEnd('/')
    $cached = $script:TokenCache[$scope]
    if ($cached -and $cached.ExpiresAt -gt [datetimeoffset]::UtcNow.AddMinutes(5)) {
        return $cached.AccessToken
    }

    # The refresh token from the first sign-in is redeemed for every other
    # resource (Power Platform API, each Dataverse environment) so the user
    # normally signs in exactly once.
    $token = $null
    if ($script:RefreshToken) {
        try {
            $token = Invoke-RestMethod -Method Post -Uri $script:TokenEndpoint -Body @{
                client_id     = $ClientId
                grant_type    = 'refresh_token'
                refresh_token = $script:RefreshToken
                scope         = "openid offline_access $scope"
            } -ContentType 'application/x-www-form-urlencoded'
        }
        catch {
            $oauthError = Get-OAuthError $_
            $reason = if ($oauthError) {
                '{0}: {1}' -f (Get-ObjectValue $oauthError 'error'), (Get-ObjectValue $oauthError 'error_description')
            }
            else {
                $_.Exception.Message
            }
            Write-Warning "Silent token acquisition for $scope failed. $reason"
            $token = $null
        }
    }

    if (-not $token) {
        if ($script:InteractiveSignIns -ge $script:MaxInteractiveSignIns) {
            throw [System.UnauthorizedAccessException]::new((
                "Interactive sign-in was already required $($script:InteractiveSignIns) times; refusing to prompt again. " +
                "Verify that the app registration has admin-consented delegated permissions for '$scope' " +
                '(Dynamics CRM > user_impersonation for Dataverse environments) and rerun.'
            ))
        }
        $script:InteractiveSignIns++
        $token = Request-DeviceCodeToken $scope
    }

    $newRefreshToken = Get-ObjectValue $token 'refresh_token'
    if ($newRefreshToken) {
        $script:RefreshToken = $newRefreshToken
    }

    $script:TokenCache[$scope] = [pscustomobject]@{
        AccessToken = $token.access_token
        ExpiresAt   = [datetimeoffset]::UtcNow.AddSeconds([int]$token.expires_in)
    }

    return $token.access_token
}

function Get-Headers {
    param(
        [string]$ResourceUrl,
        [hashtable]$AdditionalHeaders = @{}
    )

    $headers = @{
        Authorization = 'Bearer {0}' -f (Get-AccessToken $ResourceUrl)
        Accept        = 'application/json'
    }

    foreach ($name in $AdditionalHeaders.Keys) {
        $headers[$name] = $AdditionalHeaders[$name]
    }

    return $headers
}

#endregion Authentication

#region HTTP

function Invoke-JsonGet {
    # GET with retry on throttling / transient gateway errors, honouring
    # Retry-After when the service sends one.
    param(
        [string]$Uri,
        [string]$ResourceUrl,
        [hashtable]$AdditionalHeaders = @{}
    )

    $authorizationRetried = $false
    for ($attempt = 1; $attempt -le $script:MaxRequestAttempts; $attempt++) {
        # Recheck token expiry on every page and after throttling delays.
        $headers = Get-Headers $ResourceUrl $AdditionalHeaders
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
        }
        catch {
            $response = Get-ObjectValue $_.Exception 'Response'
            $statusCode = if ($response) { [int]$response.StatusCode } else { 0 }
            if ($statusCode -eq 401 -and -not $authorizationRetried) {
                $authorizationRetried = $true
                $scope = '{0}/.default' -f $ResourceUrl.TrimEnd('/')
                $script:TokenCache.Remove($scope)
                Write-Warning 'HTTP 401 received. Renewing the access token and retrying once.'
                # Token renewal has a separate budget from transient retries.
                $attempt--
                continue
            }
            if ($attempt -ge $script:MaxRequestAttempts -or $statusCode -notin $script:TransientStatusCodes) {
                throw
            }

            $retryAfter = $response.Headers.RetryAfter
            $delaySeconds = if ($retryAfter -and $retryAfter.Delta) {
                [math]::Ceiling($retryAfter.Delta.TotalSeconds)
            }
            elseif ($retryAfter -and $retryAfter.Date) {
                [math]::Ceiling(($retryAfter.Date - [datetimeoffset]::UtcNow).TotalSeconds)
            }
            else {
                [math]::Min(60, 5 * [math]::Pow(2, $attempt - 1))
            }
            $delaySeconds = [int][math]::Max(1, $delaySeconds)

            Write-Warning "HTTP $statusCode received. Retrying in $delaySeconds s (attempt $attempt of $($script:MaxRequestAttempts))."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Invoke-PagedGet {
    param(
        [string]$Uri,
        [string]$ResourceUrl,
        [hashtable]$AdditionalHeaders = @{}
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    while ($Uri) {
        $response = Invoke-JsonGet $Uri $ResourceUrl $AdditionalHeaders
        if ($null -eq $response) {
            throw "Invalid collection response from $Uri : empty response body."
        }

        $valueProperty = $response.PSObject.Properties['value']
        if ($null -eq $valueProperty -or $valueProperty.Value -isnot [System.Array]) {
            throw "Invalid collection response from $Uri : expected a 'value' array."
        }
        foreach ($row in $valueProperty.Value) {
            if ($row -isnot [pscustomobject]) {
                throw "Invalid collection response from $Uri : expected objects in the 'value' array."
            }
            $rows.Add($row)
        }

        $Uri = $response.PSObject.Properties |
            Where-Object Name -in @('@odata.nextLink', '@odata.nextlink') |
            Select-Object -ExpandProperty Value -First 1
    }

    return $rows.ToArray()
}

#endregion HTTP

#region Read the consumption report

$requiredColumns = @(
    'Agent Name',
    'Agent Id',
    'Billed credit',
    'Non-billed credit',
    'Environment Id',
    'Environment Name'
)
# Present in current PPAC exports but not guaranteed across report versions;
# they are read defensively and left blank when absent.
$optionalColumns = @(
    'Product',
    'AI Feature/Billable Feature',
    'Channel',
    'Knowledge Sources',
    'Tool Used',
    'LLM Model',
    'Scenario Name'
)

$consumptionRows = @(Import-Csv -LiteralPath $ConsumptionCsvPath)
if ($consumptionRows.Count -eq 0) {
    throw 'The PPAC consumption CSV contains no data rows.'
}

$header = @($consumptionRows[0].PSObject.Properties.Name)
$missingColumns = @($requiredColumns | Where-Object { $_ -notin $header })
if ($missingColumns) {
    throw ('Missing required CSV columns: {0}' -f ($missingColumns -join ', '))
}

$missingOptionalColumns = @($optionalColumns | Where-Object { $_ -notin $header })
if ($missingOptionalColumns) {
    Write-Warning (
        'Optional columns not present in this report version (left blank): {0}' -f
        ($missingOptionalColumns -join ', ')
    )
}

$targetEnvironmentIds = @(
    $consumptionRows.'Environment Id' |
        ForEach-Object { ConvertTo-NormalizedId $_ } |
        Where-Object { $_ } |
        Sort-Object -Unique
)

#endregion Read the consumption report

#region Environments

Write-Host 'Signing in and reading Power Platform environments...'
$environmentUri = (
    'https://api.powerplatform.com/environmentmanagement/environments' +
    '?api-version=2024-10-01'
)
$environments = @(Invoke-PagedGet $environmentUri 'https://api.powerplatform.com')
$environmentById = @{}
foreach ($environment in $environments) {
    $environmentById[(ConvertTo-NormalizedId (Get-ObjectValue $environment 'id'))] = $environment
}
Write-Host "Found $($environments.Count) environments visible to the signed-in user; $($targetEnvironmentIds.Count) referenced in the report."

#endregion Environments

#region Agents and owners

$agentByKey = @{}
$failedEnvironmentIds = [System.Collections.Generic.HashSet[string]]::new()

$dataverseHeaders = @{
    'OData-MaxVersion' = '4.0'
    'OData-Version'    = '4.0'
    Prefer             = 'odata.include-annotations="OData.Community.Display.V1.FormattedValue,Microsoft.Dynamics.CRM.lookuplogicalname"'
}
$botsQuery = (
    '/api/data/v9.2/bots' +
    '?$select=botid,name,statecode,statuscode,_ownerid_value' +
    '&$expand=' +
    'owninguser($select=systemuserid,fullname,domainname,' +
    'internalemailaddress,azureactivedirectoryobjectid),' +
    'owningteam($select=teamid,name,emailaddress,' +
    'azureactivedirectoryobjectid)'
)

foreach ($environmentId in $targetEnvironmentIds) {
    $environment = $environmentById[$environmentId]
    if (-not $environment) {
        continue
    }

    $environmentUrl = ([string](Get-ObjectValue $environment 'url')).TrimEnd('/')
    if (-not $environmentUrl) {
        continue
    }

    $environmentName = Get-ObjectValue $environment 'displayName'
    if (-not $environmentName) {
        $environmentName = $environmentId
    }

    Write-Host "Reading agents and owners from $environmentName..."

    try {
        $bots = @(Invoke-PagedGet ($environmentUrl + $botsQuery) $environmentUrl $dataverseHeaders)

        foreach ($bot in $bots) {
            $userOwner = Get-ObjectValue $bot 'owninguser'
            $teamOwner = Get-ObjectValue $bot 'owningteam'

            if ($userOwner) {
                $ownerType = 'systemuser'
                $ownerName = Get-ObjectValue $userOwner 'fullname'
                $ownerEmail = Get-ObjectValue $userOwner 'internalemailaddress'
                if (-not $ownerEmail) {
                    $ownerEmail = Get-ObjectValue $userOwner 'domainname'
                }
                $ownerEntraId = Get-ObjectValue $userOwner 'azureactivedirectoryobjectid'
            }
            elseif ($teamOwner) {
                $ownerType = 'team'
                $ownerName = Get-ObjectValue $teamOwner 'name'
                $ownerEmail = Get-ObjectValue $teamOwner 'emailaddress'
                $ownerEntraId = Get-ObjectValue $teamOwner 'azureactivedirectoryobjectid'
            }
            else {
                $ownerType = Get-ObjectValue $bot '_ownerid_value@Microsoft.Dynamics.CRM.lookuplogicalname'
                $ownerName = Get-ObjectValue $bot '_ownerid_value@OData.Community.Display.V1.FormattedValue'
                $ownerEmail = $null
                $ownerEntraId = $null
            }

            $agentKey = '{0}:{1}' -f $environmentId, (ConvertTo-NormalizedId (Get-ObjectValue $bot 'botid'))
            $agentByKey[$agentKey] = [pscustomobject]@{
                Name         = Get-ObjectValue $bot 'name'
                StateCode    = Get-ObjectValue $bot 'statecode'
                StateLabel   = Get-ObjectValue $bot 'statecode@OData.Community.Display.V1.FormattedValue'
                StatusCode   = Get-ObjectValue $bot 'statuscode'
                StatusLabel  = Get-ObjectValue $bot 'statuscode@OData.Community.Display.V1.FormattedValue'
                OwnerType    = $ownerType
                OwnerId      = ConvertTo-NormalizedId (Get-ObjectValue $bot '_ownerid_value')
                OwnerEntraId = $ownerEntraId
                OwnerName    = $ownerName
                OwnerEmail   = $ownerEmail
            }
        }

        Write-Host "  $($bots.Count) agents read."
    }
    catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) {
            # Interactive sign-in budget exhausted: this affects every
            # remaining environment, so stop instead of warning N times.
            throw
        }

        $null = $failedEnvironmentIds.Add($environmentId)
        Write-Warning ('Could not read {0} ({1}): {2}' -f $environmentName, $environmentUrl, (Get-ErrorSummary $_))
    }
}

#endregion Agents and owners

#region Join and export

$sourceFile = [System.IO.Path]::GetFileName($ConsumptionCsvPath)
$reportRows = @(foreach ($row in $consumptionRows) {
    $environmentId = ConvertTo-NormalizedId $row.'Environment Id'
    $agentId = ConvertTo-NormalizedId $row.'Agent Id'
    $environment = $environmentById[$environmentId]
    $agent = $agentByKey[('{0}:{1}' -f $environmentId, $agentId)]

    [pscustomobject][ordered]@{
        TenantId             = $TenantId
        EnvironmentId        = $environmentId
        EnvironmentName      = $row.'Environment Name'
        EnvironmentUrl       = Get-ObjectValue $environment 'url'
        AgentId              = $agentId
        AgentName            = if ($agent) { $agent.Name } else { $row.'Agent Name' }
        ConsumptionAgentName = $row.'Agent Name'
        AgentStateCode       = Get-ObjectValue $agent 'StateCode'
        AgentState           = Get-ObjectValue $agent 'StateLabel'
        AgentStatusCode      = Get-ObjectValue $agent 'StatusCode'
        AgentStatus          = Get-ObjectValue $agent 'StatusLabel'
        OwnerType            = Get-ObjectValue $agent 'OwnerType'
        OwnerDataverseId     = Get-ObjectValue $agent 'OwnerId'
        OwnerEntraObjectId   = Get-ObjectValue $agent 'OwnerEntraId'
        OwnerDisplayName     = Get-ObjectValue $agent 'OwnerName'
        OwnerEmailOrUPN      = Get-ObjectValue $agent 'OwnerEmail'
        BilledCredit         = $row.'Billed credit'
        NonBilledCredit      = $row.'Non-billed credit'
        Product              = Get-ObjectValue $row 'Product'
        AIFeature            = Get-ObjectValue $row 'AI Feature/Billable Feature'
        Channel              = Get-ObjectValue $row 'Channel'
        KnowledgeSources     = Get-ObjectValue $row 'Knowledge Sources'
        ToolUsed             = Get-ObjectValue $row 'Tool Used'
        LLMModel             = Get-ObjectValue $row 'LLM Model'
        ScenarioName         = Get-ObjectValue $row 'Scenario Name'
        SourceReportFile     = $sourceFile
        JoinStatus           = if ($agent) {
            'Matched'
        }
        elseif (-not $environment) {
            'EnvironmentNotVisible'
        }
        elseif (-not (Get-ObjectValue $environment 'url')) {
            'EnvironmentHasNoDataverseUrl'
        }
        elseif ($failedEnvironmentIds.Contains($environmentId)) {
            'EnvironmentReadFailed'
        }
        else {
            'AgentNotFound'
        }
    }
})

$outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$reportRows |
    Sort-Object EnvironmentName, AgentName, Product, AIFeature |
    Export-Csv -LiteralPath $OutputPath -Encoding utf8BOM

Write-Host ''
Write-Host "Exported $($reportRows.Count) rows to $(Resolve-Path -LiteralPath $OutputPath)"
Write-Host 'Join status summary:'
foreach ($group in ($reportRows | Group-Object JoinStatus | Sort-Object Name)) {
    Write-Host ('  {0,-30} {1,6}' -f $group.Name, $group.Count)
}

#endregion Join and export
