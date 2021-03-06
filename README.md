﻿# PKS-pwsh

## about
This is a powershell module for Managging Pivotal Enterprise Container Service (PKS).
The Modules connect directly to the PKS/UAA API and are written in Powershell.
This is an unofficial, community-build module 

![pws-pks2](https://user-images.githubusercontent.com/8255007/65012303-1e757480-d917-11e9-93e5-7205bd6bf175.gif)

## naming conventions
command names are derived from the REST API Endpints and Powershell verb´s conventions

## Pipelining
all modules shall support Pipelining, where applicable

# getting Started

1. Install The Modules

    ```Powershell
    Install-Module PKS-pwsh -Scope CurrentUser -Force
    ````

2. Connect to PKS API Endpoint
    You can use Connect-PKSapiEndpoint to connec to you cluster.
    Note: if not passed to a variable, the token will be displayed.
    The  Token will be set in *$Global:PKS_API_HEADERS* and used in subsequent commands 

    ```Powershell
    $connection=Connect-PKSapiEndpoint -PKS_API_URI https://api.pksazure.labbuildr.com -user
    ```

## Cluster Controls

Cluster Controls are used to create, modify and scale pks clusters

### Getting PKS CLuster(s)

Getting a list of PKS Clusters:

```Powershell
Get-PKSClusters
```

### Create a  new Cluster

```Powershell
New-PKSclusters -clustername snoopy -plan small -worker 1 -master_fqdn snoopy.pks.labbuildr.local
```

### Get Cluster State

```Powershell
Get-PKSclusterdetails -name snoopy
```

### Scale a PKS Cluster

```Powershell
Get-PKSclusters -name snoopy | Set-PKSclusters -worker 2
```

### remove a pks cluster

```Powershell
Get-PKSclusters -name snoopy | Remove-PKSclusters
```

### UAA User  Controls

UAA User Controls are use to create users in the PKS internal User Account and Authentication Service
Mapping of Users / SCOPES from SAML / LDAP or external UAA will be introduced soon

## Create a User and add to *pks.clusters.manage* scope

```powershell
New-PKSuaaUser -username alana -scopes pks.clusters.manage 
```

this example will ask for email and password, and than create the user and add the membership(s)
```terminal
        Supply values for the following parameters:
        email: alana@test
        Password for user alana2: ************

        id                   : 9bb39acc-314c-4c66-b625-b4e3e027d0e4
        meta                 : @{version=0; created=17.09.19 10:16:32; lastModified=17.09.19 10:16:32}
        userName             : alana2
        name                 : @{familyName=alana2; givenName=}
        emails               : {@{value=alana@test; primary=False}}
        groups               : {@{value=7f777f52-869d-41d8-8593-a5ffe4b8eef4; display=notification_preferences.read; type=DIRECT}, 
                               @{value=80a714df-0593-45ba-bfb2-2ed9fc33f08c; display=cloud_controller.read; type=DIRECT}, 
                               @{value=792b2a4c-e543-423d-80cd-2d9cbd830434; display=uaa.user; type=DIRECT}, 
                               @{value=b9b25fcd-7ea4-42b6-b203-4e6764264f7e; display=profile; type=DIRECT}…}
        approvals            : {}
        active               : True
        verified             : True
        origin               : uaa
        zoneId               : uaa
        passwordLastModified : 17.09.19 10:16:32
        schemas              : {urn:scim:schemas:core:1.0}
```

### Create a UAA User with Setting the Password, no Group Membership

*Password must be set as Secure Strings*

```Powershell
$Password = "Password123!" | ConvertTo-SecureString -AsPlainText -Force
New-PKSuaaUser -username alana3 -pass $password -email email@user.com
```

### Asssign Goup Membership Scope to a User

```powershell
Get-PKSUaaUsers -username alana3 | Set-PKSUaaGroupMember -scopes pks.clusters.admin
```
