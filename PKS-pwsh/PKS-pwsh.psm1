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
        [string]$SSOToken,
        [switch]$force
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
        if ($force.IsPresent) {
            Remove-Variable PKS_API_Headers -ErrorAction SilentlyContinue
            Remove-Variable PKS_API_Headers -ErrorAction SilentlyContinue
            Remove-Variable PKS_API_ClientCredentials -ErrorAction SilentlyContinue
            Remove-Variable PKS_API_Credentials -ErrorAction SilentlyContinue
        }
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
        Write-Host "Connected to $PKS_API_BASEURI with $($Response.Scope)"
        Write-Output $Response
    }
}


function Update-PKSAccessToken {
    [CmdletBinding()]
    param(
        $PKS_API_BaseUri = $Global:PKS_API_BaseUri
    )

    begin { 
        $METHOD = "POST"
        $URI = "$($PKS_API_BaseUri):8443/oauth/token"
        $clientid = 'pks_cli:'
        $client_encoded = [System.Text.Encoding]::UTF8.GetBytes($clientid)
        $client_base64 = [System.Convert]::ToBase64String($client_encoded)
        $headers = @{
            'content-type'  = "application/x-www-form-urlencoded"
            'authorization' = "Basic $client_base64"    
        }  
        $Body = @{
            'grant_type'    = "refresh_token"
            'refresh_token' = $Global:Refresh_token
            'token_format'  = "opaque"
        } 
    }
    process {
        #    client_id=app&client_secret=appclientsecret&grant_type=refresh_token&token_format=opaque&refresh_token=9655f63edf2e476ebb6abea944111590-r 
        try {  
            if ($Global:SkipCertificateCheck) {            
                $Response = Invoke-RestMethod -SkipCertificateCheck `
                    -Method $METHOD -Headers $headers -Body $body `
                    -UseBasicParsing -Uri "$($Global:PKS_API_BaseUri):8443/oauth/token" 
            }   
            else {
                $Response = Invoke-RestMethod `
                    -Method $METHOD -Headers $headers -Body $body `
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
        Write-Host "Connected to $PKS_API_BASEURI with $($Response.Scope)"
        Write-Output $Response
    }
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

function Set-PKSclusters {
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
        $Method,
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'infile')]
        $Query,
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'infile')]
        $ContentType = 'application/json', 
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        $Body,
        [Parameter(Mandatory = $true, ParameterSetName = 'infile')]
        $InFile
    )
    if ($Global:PKS_API_Headers) {
        $Headers = $Global:PKS_API_Headers
        Write-Verbose ($Headers | Out-String)
        Write-Verbose "==> Calling $uri"
        $Parameters = @{
            UseBasicParsing = $true 
            Uri             = $Uri
            Method          = $Method
            Headers         = $Headers
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
                if ($query) {
                    $Parameters.Add('body', $query)
                    Write-Verbose $Query | Out-String
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
    $clientid = 'pks_cli:'
    $client_encoded = [System.Text.Encoding]::UTF8.GetBytes($clientid)
    $client_base64 = [System.Convert]::ToBase64String($client_encoded)
    $headers = @{
        'authorization' = "Basic $client_base64"    
    } 
    $METHOD = "GET"
    $URI = "$($Global:PKS_API_BaseUri):8443/logout.do"
    $Parameters = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $headers
    }

    if ($Global:SkipCertificateCheck) {
        $Parameters.Add('SkipCertificateCheck', $True)
    }
    Invoke-RestMethod @Parameters
    Remove-Variable PKS_API_Headers -ErrorAction SilentlyContinue
    Remove-Variable PKS_API_Headers -ErrorAction SilentlyContinue
    Remove-Variable PKS_API_ClientCredentials -ErrorAction SilentlyContinue
    Remove-Variable PKS_API_Credentials -ErrorAction SilentlyContinue
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


function New-PKSUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('username', 'un')]$user,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string]$clustername,
        [Parameter(Mandatory = $false)][ValidateSet('v1beta1')]$apiVersion = 'v1'
    )
    begin {
        $METHOD = "POST"
        $BODY = @{
            "user" = $user
        } | ConvertTo-Json    	
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/clusters/$clusterName/binds"
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
        $Response = @()
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

function New-PKSuaaUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('user', 'un')]$username,
        [Parameter(Mandatory = $true, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('mail', 'em')]$email,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [securestring][alias('pass', 'pw')]$SecurePassword,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string]$familyname,
        [Parameter(Mandatory = $false, ParameterSetName = 'name',
            ValueFromPipelineByPropertyName = $true)]
        [string]$givenname
    )
    begin {
        $Response = @()
        $METHOD = "POST"
    }
    process {
        if (!$SecurePassword) {
            $SecurePassword = Read-Host -Prompt "Password for user $username" -AsSecureString 
        }
        $Credentials = New-Object System.Management.Automation.PSCredential($username, $Securepassword)
        $Password = ($Credentials.GetNetworkCredential()).password
        if (!$familyName) {
            $familyname = $username
        }
        $BODY = @{
            "username" = $username
            "name"     = @{
                "familyName" = $familyname
                "givenName"  = $givenname
            }                
            "emails"   = @(
                @{
                    "primary" = "true"
                    "value"   = $email
                }
            )
            "password" = $password
        } | ConvertTo-Json    	
        write-verbose ($body | Out-String)
        $URI = "$($Global:PKS_API_BaseUri):8443/Users"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD -Body $BODY | ConvertFrom-Json
    }    
    end { Write-Output $Response }
} 

# b7975672-075c-49bf-8d63-ce81653a49bf
Function Set-PKSUaaGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'uname', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'uid', ValueFromPipelineByPropertyName = $true)]
        [string][alias('id')]$userid,
        [Parameter(Mandatory = $false, ParameterSetName = 'uid', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'uname', ValueFromPipelineByPropertyName = $true)]
        [string][alias('user')]$username,
        [Parameter(Mandatory = $false, ParameterSetName = 'uid', ValueFromPipelineByPropertyName = $true)]
        [object[]]$schemas,
        [Parameter(Mandatory = $true, ParameterSetName = 'uid', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'uname', ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('pks.clusters.admin', 'pks.clusters.manage')]
        [string[]]$scopes
    )
    begin {
        $Response = @()
        $METHOD = "get"
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'uname' {
                $UserID = (Get-PKSUaaUsers -username $username).id
            }
        }
        foreach ($Scope in $Scopes) {
            $body = @()
            $Query = @{
                'scheme' = "openid"
                'filter' = "displayName Eq `"$scope`""
            } 
            $GroupID = (Get-PKSUaaGroups -displayName $Scope).id
            $URI = "$($GLOBAL:PKS_API_BaseUri):8443/Groups/$GroupID/members"  
            $BODY = @{  
                "origin" = "uaa"
                "type"   = "USER"
                "value"  = "$UserID"
            } | ConvertTo-Json
            $Response += Invoke-PKSapirequest -uri $URI -Method Post -ContentType "application/json" -Body $body | ConvertFrom-Json

        }
    }    
    end { Write-Output $Response }
} 

function Get-PKSUaaUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'name',ValueFromPipelineByPropertyName = $true)]
        [string][alias('name')]$username,
        [Parameter(Mandatory = $false, ParameterSetName = 'id',ValueFromPipelineByPropertyName = $true)]
        [string][alias('userid')]$id
    )
    begin {
        $Response = @()
        $METHOD = "get"
    }
    process {
        $Query = @()
        if ($username) {
            $Query = @{
                'scheme' = "openid"
                'filter' = "userName Eq `"$username`""
            } 
        }
        if ($id) {
            $Query = @{
                'scheme' = "openid"
                'filter' = "id Eq `"$id`""
            } 
        }
        $URI = "$($GLOBAL:PKS_API_BaseUri):8443/Users"
        $Response += (Invoke-PKSapirequest -uri $URI -Method Get  -ContentType "application/json" -Query $Query | ConvertFrom-Json).resources
    }    
    end { Write-Output $Response }
} 



function Remove-PKSUaaUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'name',ValueFromPipelineByPropertyName = $false)]
        [string][alias('name')]$username,
        [Parameter(Mandatory = $true, ParameterSetName = 'uid',ValueFromPipelineByPropertyName = $true)]
        [string][alias('userid')]$id,
        [Parameter(Mandatory = $false, ParameterSetName = 'uid', ValueFromPipelineByPropertyName = $true)]
        [object[]]$schemas

    )
    begin {
        $Response = @()
        $METHOD = "Delete"
    }
    process {
        if ($username) {
            $id = (Get-PKSUaaUsers -username $username).id
            } 

        $URI = "$($GLOBAL:PKS_API_BaseUri):8443/Users/$id"
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD  -ContentType "application/json"  | ConvertFrom-Json
    }    
    end { Write-Output $Response }
} 

function Get-PKSUaaClients {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'ID',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('id')]$ClientID
    )
    begin {
        $Response = @()
        $METHOD = "get"
    }
    process {
        $Query = @()
        if ($username) {
            $Query = @{
                'scheme' = "openid"
                'filter' = "userName Eq `"$ClientID`""
            } 
        }
        $URI = "$($GLOBAL:PKS_API_BaseUri):8443/oauth/clients"
        $Response += (Invoke-PKSapirequest -uri $URI -Method Get  -ContentType "application/json" -Query $Query | ConvertFrom-Json).resources
    }    
    end { 
        Write-Output $Response 
    }
} 


function Get-PKSUaaGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'displayName',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('GroupName')]$displayName,
        [Parameter(Mandatory = $false, ParameterSetName = 'id',
            ValueFromPipelineByPropertyName = $true)]
        [string][alias('GroupID')]$id     
    )
    begin {
        $Response = @()
        $METHOD = "get"
    }
    process {
        $Query = @()
        if ($id) {
            $Query = @{
                'scheme' = "openid"
                'filter' = "id Eq `"$id`""
            } 
        }
        if ($displayName) {
            $Query = @{
                'scheme' = "openid"
                'filter' = "displayName Eq `"$displayName`""
            } 
        }
        $URI = "$($GLOBAL:PKS_API_BaseUri):8443/Groups"
        $Response += (Invoke-PKSapirequest -uri $URI -Method Get  -ContentType "application/json" -Query $Query | ConvertFrom-Json).resources
    }    
    end { 
        Write-Output $Response 
    }
} 