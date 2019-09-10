function Unblock-PKSSSLCerts {

    Add-Type -TypeDefinition @"

	    using System.Net;

	    using System.Security.Cryptography.X509Certificates;

	    public class TrustAllCertsPolicy : ICertificatePolicy {

	        public bool CheckValidationResult(

	            ServicePoint srvPoint, X509Certificate certificate,

	            WebRequest request, int certificateProblem) {

	            return true;

	        }

	    }

"@

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy



}
function Connect-PKSapiEndpoint {
    [CmdletBinding()]
    param(
        # the refres token provided from your Pivotal Net Profile
        [Parameter(Mandatory = $false, ParameterSetName = 'User', ValueFromPipelineByPropertyName = $true)]
        [pscredential]$PKS_API_Credentials = $Global:PKS_API_Credentials,
        [Parameter(Mandatory = $true, ParameterSetName = 'User')]
        [switch]$user,
        [Parameter(Mandatory = $false, ParameterSetName = 'client', ValueFromPipelineByPropertyName = $true)]
        [pscredential]$PKS_API_ClientCredentials = $Global:PKS_API_ClientCredentials,
        [Parameter(Mandatory = $True, ParameterSetName = 'Client')]
        [switch]$Client,
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        $PKS_API_URI = $Global:PKS_API_BaseUri,
        [switch]$trustCert,
        [Parameter(Mandatory = $True, ParameterSetName = 'SSO')]
        [switch]$SSO,
        [Parameter(Mandatory = $false, ParameterSetName = 'SSO')]
        [string]$SSOToken
    )
    Begin {
        if ($trustCert.IsPresent) {
            if ($PSVersiontable.PSVersion -ge 6.0) {
                $global:SkipCertificateCheck = $TRUE
            }
            else {
                Unblock-PKSSSLCerts    
            }
            
        }  
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12  
        $clientid = 'pks_cli:'
        $client_encoded = [System.Text.Encoding]::UTF8.GetBytes($clientid)
        $client_base64 = [System.Convert]::ToBase64String($client_encoded)
        $headers = @{
            'content-type'  = "application/x-www-form-urlencoded"
            'authorization' = "Basic $client_base64"    
        }          
    }
    Process {
        $Global:PKS_API_BaseUri = $PKS_API_URI
        Write-Verbose $Global:PKS_API_BaseUri
        switch ($PsCmdlet.ParameterSetName) {
            'SSO' {
                if (!$SSOToken) {
                    $SSOToken = Read-Host -prompt "Please enter your Temporary Code from $($PKS_API_BaseUri):8443/passcode"
                    $body = "grant_type=password&passcode=$SSOToken"
                }
            }
            'USER' {
                if (!$PKS_API_Credentials) {
                    $username = Read-Host -Prompt "Please Enter PKS username"
                    $SecurePassword = Read-Host -Prompt "Password for user $username" -AsSecureString
                    $PKS_API_Credentials = New-Object System.Management.Automation.PSCredential($username, $Securepassword)
                }
                $password = $([System.Web.HttpUtility]::UrlEncode(($PKS_API_Credentials.GetNetworkCredential()).password))
                $Body = @{
                    'grant_type' = "password"
                    'username'   = $([System.Web.HttpUtility]::UrlEncode($PKS_API_Credentials.username))
                    #                'token_format' = "opaque"
                    'password'   = $password
                }
   
            }
            'CLIENT' {
                if (!$PKS_API_ClientCredentials) {
                    $client_id = Read-Host -Prompt "Please Enter PKS PKS_API_anager Client"
                    $client_secret = Read-Host -Prompt "Secret for $client_id" -AsSecureString
                    $PKS_API_ClientCredentials = New-Object System.Management.Automation.PSCredential($client_id, $client_secret)
                
                }
                $clientid = "$([System.Web.HttpUtility]::UrlEncode($PKS_API_ClientCredentials.username))" # :$([System.Web.HttpUtility]::UrlEncode(($PKS_API_ClientCredentials.GetNetworkCredential()).password))"
                $Body = @{
                    'grant_type'    = "client_credentials"
                    'client_id'     = $([System.Web.HttpUtility]::UrlEncode($PKS_API_ClientCredentials.username))
                    'token_format'  = "opaque"
                    'client_secret' = $([System.Web.HttpUtility]::UrlEncode(($PKS_API_ClientCredentials.GetNetworkCredential()).password))
                } 
                $headers = @{'content-type' = "application/x-www-form-urlencoded;charset=utf-8"
                    'Accept'                = "application/json"

                }
            }
        }    

        

        $VerbosePreference
        Write-Verbose ($body | Out-String)
        Write-Verbose ( $headers | Out-String ) 
        try {  
            if ($Global:SkipCertificateCheck) {            
                $Response = Invoke-RestMethod -SkipCertificateCheck `
                    -Method POST -Headers $headers -Body $body `
                    -UseBasicParsing -Uri "$($Global:PKS_API_BaseUri):8443/oauth/token" 
            }   
            else {
                $Response = Invoke-RestMethod `
                    -Method POST -Headers $headers -Body $body `
                    -UseBasicParsing -Uri "$($Global:PKS_API_BaseUri):8443/oauth/token"
            }
        }
        catch {
            Get-PKSWebException -ExceptionMessage $_
            switch ($PsCmdlet.ParameterSetName) {
                'USER' {
                    Remove-Variable PKS_API_Credentials
                } 
                'CLIENT' {
                    Remove-Variable PKS_API_ClientCredentials
                } 
            }
            Break
        }
        #>
    }
    End {
        switch ($PsCmdlet.ParameterSetName) {
            'Client' {
                $Global:PKS_API_ClientCredentials = $PKS_API_ClientCredentials
            }
            'User' {
                $Global:PKS_API_Credentials = $PKS_API_Credentials
            }
        }
        
        $Global:PKS_API_Headers = @{
            'Authorization' = "Bearer $($Response.access_token)"
        }
        $Global:Refresh_token = $Response.Refresh_token
        Write-Host "Connected to PKS_API_ with $($Response.Scope)"
        Write-Output $Response
    }
}


<#curl 'http://localhost/oauth/token' -i -X POST \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'client_id=app&client_secret=appclientsecret&grant_type=refresh_token&token_format=opaque&refresh_token=9655f63edf2e476ebb6abea944111590-r'
POST /oauth/token HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: localhost

client_id=app&client_secret=appclientsecret&grant_type=refresh_token&token_format=opaque&refresh_token=9655f63edf2e476ebb6abea944111590-r
HTTP/1.1 200 OK
Content-Length: 1140
Pragma: no-cache
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Cache-Control: no-store
Content-Type: application/json;charset=UTF-8

{
  "access_token" : "cd29c86b2edf46fba173b3ca4b6687ad",
  "token_type" : "bearer",
  "id_token" : "eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHBzOi8vbG9jYWxob3N0OjgwODAvdWFhL3Rva2VuX2tleXMiLCJraWQiOiJsZWdhY3ktdG9rZW4ta2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOiIxOGFiZjM0YS00Yzc5LTRhMTAtODJmMS1lNjIwMDJlNGVlN2UiLCJhdWQiOlsiYXBwIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLCJleHAiOjE1Njc4NTgyNTcsImlhdCI6MTU2NzgxNTA1NywiYW1yIjpbInB3ZCJdLCJhenAiOiJhcHAiLCJzY29wZSI6WyJvcGVuaWQiXSwiZW1haWwiOiI0UmZFRk9AdGVzdC5vcmciLCJ6aWQiOiJ1YWEiLCJvcmlnaW4iOiJ1YWEiLCJqdGkiOiIzNmY5NmU4MDBmYjk0ZDcyOTc0ODdmNDY1MTI2YzIyZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjbGllbnRfaWQiOiJhcHAiLCJjaWQiOiJhcHAiLCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiI0UmZFRk9AdGVzdC5vcmciLCJyZXZfc2lnIjoiODI4YmU2ZWYiLCJ1c2VyX2lkIjoiMThhYmYzNGEtNGM3OS00YTEwLTgyZjEtZTYyMDAyZTRlZTdlIiwiYXV0aF90aW1lIjoxNTY3ODE1MDU3fQ.4VKHbNpoD8p2ee0HWscxpI7IEMqtKihiy5sA2etF7iY",
  "refresh_token" : "9655f63edf2e476ebb6abea944111590-r",
  "expires_in" : 43199,
  "scope" : "scim.userids cloud_controller.read password.write cloud_controller.write openid",
  "jti" : "cd29c86b2edf46fba173b3ca4b6687ad"
}
Request Parameters

Parameter	Type	Constraints	Description
grant_type	String	Required	the type of authentication being used to obtain the token, in this case refresh_token#>
#https://api.pks.labbuildr.local:9021/actuator/info


function Update-PKSAccessToken {
    [CmdletBinding()]
    param(
        $PKS_API_BaseUri = $Global:PKS_API_BaseUri
    )
    $METHOD = "POST"
    $URI = "$($PKS_API_BaseUri):8443/oauth/token"
    
    $Headers = @{ 'content-type' = "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
        'Accept'                 = "application/json"
    }
    try {
        $Response = Invoke-WebRequest -Headers $Headers -Uri $URI -Method $METHOD -SkipCertificateCheck -ContentType "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
    }
    catch {
        Get-PKSWebException  -ExceptionMessage $_
        break
    }
    write-verbose ($response | Out-String)
    write-output $response.content | ConvertFrom-Json
}



function Get-PKSactuator_health {
    [CmdletBinding()]
    param(
        $PKS_API_BaseUri = $Global:PKS_API_BaseUri
    )
    $METHOD = "GET"
    $Myself = ($MyInvocation.MyCommand.Name.Substring(7) -replace "_", "/").ToLower()
    # $response = Invoke-WebRequest -Method $Method -Uri $Global:PKS_API_BaseUri/api/v0/$Myself -Headers $Global:PKS_API_Headers
    $URI = "$($PKS_API_BaseUri):9021/$Myself"
    
    $Headers = @{ 'content-type' = "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
        'Accept'                 = "application/json"
    }
    try {
        $Response = Invoke-WebRequest -Headers $Headers -Uri $URI -Method $METHOD -SkipCertificateCheck -ContentType "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
    }
    catch {
        Get-PKSWebException  -ExceptionMessage $_
        break
    }
    write-verbose ($response | Out-String)
    write-output $response.content | ConvertFrom-Json
}


function Get-PKSactuator {
    [CmdletBinding()]
    param(
        $PKS_API_BaseUri = $Global:PKS_API_BaseUri
    )
    $METHOD = "GET"
    $Myself = ($MyInvocation.MyCommand.Name.Substring(7) -replace "_", "/").ToLower()
    # $response = Invoke-WebRequest -Method $Method -Uri $Global:PKS_API_BaseUri/api/v0/$Myself -Headers $Global:PKS_API_Headers
    $URI = "$($PKS_API_BaseUri):9021/$Myself"
    
    $Headers = @{ 'content-type' = "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
        'Accept'                 = "application/json"
    }
    try {
        $Response = Invoke-WebRequest -Headers $Headers -Uri $URI -Method $METHOD -SkipCertificateCheck -ContentType "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8"
    }
    catch {
        Get-PKSWebException  -ExceptionMessage $_
        break
    }
    write-verbose ($response | Out-String)
    write-output ($response.content | ConvertFrom-Json)._links
}

function Get-PKSactuator_info {
    [CmdletBinding()]
    param(
        $PKS_API_BaseUri = $Global:PKS_API_BaseUri
    )
    $METHOD = "GET"
    $Myself = ($MyInvocation.MyCommand.Name.Substring(7) -replace "_", "/").ToLower()
    # $response = Invoke-WebRequest -Method $Method -Uri $Global:PKS_API_BaseUri/api/v0/$Myself -Headers $Global:PKS_API_Headers
    $URI = "$($PKS_API_BaseUri):9021/$Myself"

    Write-Verbose ($Headers | Out-String)
    $Headers = @{ }
    $Headers.Add("$($Global:PKS_API_Headers.Keys)", "$($Global:PKS_API_Headers.Values)")
    Write-Verbose ($Headers | Out-String)
    $Headers.Add('content-type', "application/vnd.spring-boot.actuator.v2+json; charset=UTF-8")
    $Headers.Add('Accept', "application/json")
    Write-Verbose ($Headers | Out-String)

    try {
        $Response = Invoke-WebRequest -Headers $Headers -Uri $URI -Method $METHOD -SkipCertificateCheck 
    }
    catch {
        Get-PKSWebException  -ExceptionMessage $_
        break
    }
    write-verbose ($response | Out-String)
    write-output ($response.content | ConvertFrom-Json)
}


function Get-PKSclusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername')]$name,
        [Parameter(Mandatory = $false)][ValidateSet('v1', 'v1beta1')]$apiVersion = 'v1'
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        if ($name) {
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$name "
        }
        else {
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)"
        }
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}


function Remove-PKSclusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername')]$name,
        [Parameter(Mandatory = $false)][ValidateSet('v1')]$apiVersion = 'v1'
    )
    begin {
        $METHOD = "DELETE"
        $Myself = $MyInvocation.MyCommand.Name.Substring(10)
    }
    process {

        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$name "

        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}

function Update-PKSclusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name', ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername')]$name,
        [Parameter(Mandatory = $true, ParameterSetName = 'name', ValueFromPipelineByPropertyName = $true)]        
        [string][alias('kubernetes_worker_instances', 'wi')]
        [ValidateRange(1, 20)]$worker,
        [Parameter(Mandatory = $false, ParameterSetName = 'name', ValueFromPipelineByPropertyName = $true)]
        [alias('ir')][string[]]$insecure_registries,
        [Parameter(Mandatory = $false)][ValidateSet('v1')]$apiVersion = 'v1'
    )
    begin {
        $METHOD = "PATCH"
        $Myself = $MyInvocation.MyCommand.Name.Substring(10)
    }
    process {

        $BODY = @{
            "insecure_registries"         = @($insecure_registries)
            "kubernetes_worker_instances" = $worker
        } | ConvertTo-Json
        

        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$name "

        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD  -Body $BODY | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}


function Get-PKScompute_profiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('profilename')]$name,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1beta1'
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
        $Myself.Replace('_', '-')
    }
    process {
        if ($name) {
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$name "
        }
        else {
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)"
        }
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}

function Get-PKSusages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1beta1'
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$user"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}

function Get-PKSerror {
    [CmdletBinding()]
    param(
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$($Myself)"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}
function Get-PKSclusterdetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername')]$name
    )
    begin { 
        $Response = @()
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
   
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/v1/$($Myself)/$name"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end {
        Write-Output $Response  
    }
}

function Get-PKSservice_instances {
    [CmdletBinding()]
    param(

    )
    begin { 
        $Response = @()
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
   
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$($Myself)"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end {
        Write-Output $Response  
    }
}

function New-PKSclusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername', 'cn')]$name,
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('plan_name', 'pn')]$plan,
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('kubernetes_worker_instances', 'wi')]
        [ValidateRange(1, 20)]$worker,
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('kubernetes_master_host', 'km')]$master_fqdn
    )
    begin { 
        $Response = @()
        $METHOD = "POST"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
   
    process {
        $Body = @{
            'name'      = $name
            'plan_name' = $plan
            parameters  = @{
                'kubernetes_master_host'      = $master_fqdn
                'kubernetes_worker_instances' = $worker
            }
        } | ConvertTo-Json
        $URI = "$($Global:PKS_API_BaseUri):9021/v1/$($Myself)"
        Write-Verbose ("Invoke-PKSapirequest -uri $URI -Method $METHOD -body $body" | Out-String )
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD -body $Body | ConvertFrom-Json
    }    
    end {
        Write-Output $Response  
    }
}

function Invoke-PKSapirequest {
    [CmdletBinding(HelpUri = "")]
    #[OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'infile')]
        $uri,
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'infile')]
        [ValidateSet('Get', 'Delete', 'Put', 'Post', 'Patch')]
        $Method = 'Get',
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'infile')]
        $ContentType = 'application/json', 
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        $Body,
        [Parameter(Mandatory = $true, ParameterSetName = 'infile')]
        $InFile
    )
    if ($Global:PKS_API_Headers) {
        Write-Verbose "==> Calling $uri"
        $Parameters = @{
            UseBasicParsing = $true 
            Uri             = $Uri
            Method          = $Method
            Headers         = $Global:PKS_API_Headers
            ContentType     = $ContentType
        }
        switch ($PsCmdlet.ParameterSetName) {    
            'infile' {
                $Parameters.Add('InFile', $InFile) 
            }
            default {
                if ($Body) {
                    $Parameters.Add('body', $body)
                }
            }
        }
        if ($Global:SkipCertificateCheck) {
            $Parameters.Add('SkipCertificateCheck', $True)
        }
        Write-Verbose ( $Parameters | Out-String )    
        try {
            $Result = Invoke-WebRequest @Parameters
        }
        catch {
            # Write-Warning $_.Exception.Message
            Get-PKSWebException -ExceptionMessage $_
            Break
        }
    }
    else {
        Write-Warning " PKS_API_Headers are not present. Did you connect to PKS_API  using connect-PKSAPI ? "
        break
    }
    
    Write-Output $Result.Content
}

# /v1/clusters/{clusterName}/binds/{userName}


function Get-PKSclusterBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('clustername', 'cn')]$name,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false)][ValidateSet('v1')]$apiVersion = 'v1'
    )
    begin {
        $METHOD = "GET"
    }
    process {

        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/clusters/$($name)/binds/$user"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}



function Get-PKSSessions {
    [CmdletBinding()]
    param(
    )
    $METHOD = "GET"
    $Myself = ($MyInvocation.MyCommand.Name.Substring(7) -replace "_", "/").ToLower()
    # $response = Invoke-WebRequest -Method $Method -Uri $Global:PKS_API_BaseUri/api/v0/$Myself -Headers $Global:PKS_API_Headers
    $URI = "$Global:PKS_API_BaseUri/api/v0/$Myself/current"
    $Response = Invoke-PKSapirequest -uri $URI -Method $METHOD
    ($response | ConvertFrom-Json).session
}


# DELETE /api/v0/sessions
function Disconnect-PKSsession {
    [CmdletBinding()]
    param(
    )
    $METHOD = "DELETE"
    $Body = @{ } | ConvertTo-Json -compress
    Write-Verbose $Body
    $Myself = ($MyInvocation.MyCommand.Name.Substring(14) -replace "_", "/").ToLower()
    # $response = Invoke-WebRequest -Method $Method -Uri $Global:PKS_API_BaseUri/api/v0/$Myself -Headers $Global:PKS_API_Headers
    $URI = "$Global:PKS_API_BaseUri/api/v0/$Myself"
    $Response = Invoke-PKSapirequest -uri $URI -Method $METHOD -Body $Body
    ($response | ConvertFrom-Json).session
}

function Get-PKSquotas {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1beta1'
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$user"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}    
function New-PKSquotas {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [Int64]$cpu,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [double][alias('mem')]$memory,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1beta1'
    )
    begin {
        $METHOD = "POST"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
        $BODY = @{
            "limit" = @{
                "cpu"    = $cpu
                "memory" = $memory
            }
            "owner" = $user
        } | ConvertTo-Json    	
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD -Body $BODY 
    }    
    end { Write-Output $Response }
}   

function Set-PKSquotas {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [Int64]$cpu,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [double][alias('mem')]$memory,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1beta1'
    )
    begin {
        $METHOD = "PATCH"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
        $BODY = @{
            "limit" = @{
                "cpu"    = $cpu
                "memory" = $memory
            }
            "owner" = $user
        } | ConvertTo-Json    	
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$user"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD -Body $BODY 
    }    
    end { Write-Output $Response }
}   