# PKS-pwsh

## about
This is a powershell module for Managging Pivotal Enterprise Container Service (PKS).
The Modules connect directly to the PKS API and are written in Powershell.
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

### UAA User Handling
