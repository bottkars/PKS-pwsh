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
        $client_id = 'PKS_API_'
  
    }
    Process {
        $Global:PKS_API_BaseUri = $PKS_API_URI
        Write-Verbose $Global:PKS_API_BaseUri
        # $body= "grant_type=password&username=$($PKS_API_Credentials.UserName)&password=$(($PKS_API_Credentials.GetNetworkCredential()).password)"
        switch ($PsCmdlet.ParameterSetName) {
            'SSO' {
                if (!$SSOToken) {
                    $SSOToken = Read-Host -prompt "Please enter your Temporary Code from $PKS_API_BaseUri/uaa/passcode"
                    $body = "grant_type=password&passcode=$SSOToken"
                    $clientid = "$($client_id):"
                }
            }
            'USER' {
                if (!$PKS_API_Credentials) {
                    $username = Read-Host -Prompt "Please Enter PKS PKS_API_anager username"
                    $SecurePassword = Read-Host -Prompt "Password for user $username" -AsSecureString
                    $PKS_API_Credentials = New-Object System.Management.Automation.PSCredential($username, $Securepassword)
                }
                $clientid = "$($client_id):"
                $body = "grant_type=password&username=$([System.Web.HttpUtility]::UrlEncode($PKS_API_Credentials.UserName))&password=$([System.Web.HttpUtility]::UrlEncode(($PKS_API_Credentials.GetNetworkCredential()).password))"
            }
            'CLIENT' {
                #   client_id=admin&client_secret=${ADMIN_CLIENT_SECRET}&grant_type=client_credentials&token_format=opaque
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
                } #| ConvertTo-Json
            }
        }    

        # $client_encoded = [System.Text.Encoding]::UTF8.GetBytes($clientid)
        # $client_base64 = [System.Convert]::ToBase64String($client_encoded)
        
        $headers = @{'content-type' = "application/x-www-form-urlencoded;charset=utf-8"
            'Accept'                = "application/json"
        }
        $VerbosePreference
        Write-verbose "Using uri $($Global:PKS_API_BaseUri):8443/oauth/token"
        Write-Verbose "Using Body: $body"
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
        Write-Host "Connected to PKS_API_ with $($Response.Scope)"
        Write-Output $Response
    }
}

#https://api.pks.labbuildr.local:9021/actuator/info
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
        [Parameter(Mandatory=$false)][ValidateSet('v1','v1beta1')]$apiVersion
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        if ($name){
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)/$name "
        }
        else {
            $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)"
        }
        $Response += Invoke-PKSapirequest -uri $URI -Method $METHOD | ConvertFrom-Json
    }    
    end { Write-Output $Response }
}

function Get-PKSusage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][ValidateSet('v1beta1')]$apiVersion
    )
    begin {
        $METHOD = "GET"
        $Myself = $MyInvocation.MyCommand.Name.Substring(7)
    }
    process {
        $URI = "$($Global:PKS_API_BaseUri):9021/$apiversion/$($Myself)"
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
        $ContentType = 'application/json;charset=utf-8', 
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
# POST /api/v0/certificates/generate


# GET /api/v0/deployed/director/credentials



<#
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
    #>