# PKS-pwsh


This is a powwershell module for Managging Pivotal Enterprise Container Service (PKS).
The Modules connect directly to the PKS API and are written in Powershell.

![pks-pwsh](https://user-images.githubusercontent.com/8255007/64982997-cc553480-d8bf-11e9-8a48-34d2e4a41fd4.gif)


# getting Started

1. Install The Modules

```Powershell
Install-Module PKS-pwsh -Scope CurrentUser -Force
```

2. Connect to PKS API Endpoint
You can use Connect-PKSapiEndpoint to connec to you cluster.
Note: if not passed to a variable, the token will be displayed.

The  Token will be set in *$Global:PKS_API_HEADERS* and used in subsequent commands 
```
$connection=Connect-PKSapiEndpoint -PKS_API_URI https://api.pksazure.labbuildr.com -user
```

## Getting PKS CLuster(s)


