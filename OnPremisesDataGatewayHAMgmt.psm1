If ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "Current powershell Version is " + $PSVersionTable.PSVersion + ", version 5 is required for this module."
    return
}

$script:nullString = (New-Guid).Guid
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Add-Type -TypeDefinition @"
   public enum LoadBalancingType
   {
        Failover = 0,
        Random = 1
   }
"@

<#
 .SYNOPSIS

  Get default environment.

 .DESCRIPTION

  This function get environment from on-premises data gateway configuration.
#>
Function Get-DefaultEnvironment {
    $script:adClientId = ($settings | ? { $_.name -eq "AzureADClientID" }).value
    if ($script:adClientId -eq $null) { $script:adClientId = "ea0616ba-638b-4df5-95b9-636659ae5121" }

    $script:adAuthority = ($settings | ? { $_.name -eq "AzureADAuthorityAddress" }).value

    $script:adRedirect = ($settings | ? { $_.name -eq "AzureADRedirectAddress" }).value
    if ($script:adRedirect -eq $null) { $script:adRedirect = "urn:ietf:wg:oauth:2.0:oob" }

    $script:adResource = ($settings | ? { $_.name -eq "AzureADResource" }).value
    $script:gsEndpoint = ($settings | ? { $_.name -eq "GlobalServiceEndpoint" }).value
    $script:gsBackendUriOverride = ($settings | ? { $_.name -eq "BackendUriOverride" }).value
}

<#
 .SYNOPSIS

  Get email properties.

 .DESCRIPTION

  This function setup environment by getting email properties from global service.

 .PARAMETER EmailAddress

  The email address.
#>
Function Get-EmailProperties(
    [Parameter(Mandatory=$true)]
    [string]$EmailAddress) {
    try {
        $uri = $script:gsEndpoint + "/powerbi/globalservice/v201606/environments/discover?user=" + $EmailAddress
        $epResponse = Invoke-WebRequest -Uri $uri -Method Post

        $cloudEnv = $epResponse.Content | ConvertFrom-Json
        $gateway = $cloudEnv.clients | ? { $_.name -eq "powerbi-gateway" }
        $pbiBackend = $cloudEnv.services | ? { $_.name -eq "powerbi-backend" }
        $aadBackend = $cloudEnv.services | ? { $_.name -eq "aad" }
        $script:adClientId = $gateway.appId
        $script:adAuthority = $aadBackend.endpoint
        $script:adRedirect = $gateway.redirectUri
        $script:adResource = $pbiBackend.resourceId
        $script:gsEndpoint = $pbiBackend.endpoint
        return $true
    }
    catch {
        Write-WebRequestFailure
        return $false
    }
    
}

<#
 .SYNOPSIS

  Get response from web exception.

 .DESCRIPTION

  This function return response from web exception.

 .PARAMETER Exception

  The web exception.
#>
Function Get-ResponseFromWebException() {
    If ($_.Exception.Response) {
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        return $reader.ReadToEnd()
    }
}

<#
 .SYNOPSIS

  Write web request failure.

 .DESCRIPTION

  This function write web request failure to host.
#>
Function Write-WebRequestFailure() {
    If ($_.ErrorDetails.Message) {
        try {
            If (($_.ErrorDetails.Message | ConvertFrom-Json).error.code -eq "TokenExpired") {
                Write-Warning "Token expired, please login again."
                return
            }
        } catch {
            # Ignore json convert exception
        }
    }

    Write-Warning $_.Exception.Message
    $responseBody = Get-ResponseFromWebException
    If ($responseBody) { Write-Warning $responseBody }
}

<#
 .SYNOPSIS

  Clean up user account.

 .DESCRIPTION

  This function clean up token, backend uri and gateway regions.
#>
Function Remove-OnPremisesDataGatewayUserAccount() {
    $script:token = $null
    $script:backendUri = $null
    $script:selectedBackend = $null
    $script:allRegions = $null
}

<#
 .SYNOPSIS

  Set up user account.

 .DESCRIPTION

  This function read setting from on-premises data gateway configuration, get token from active directory and get 
  backend uri from global service.

 .PARAMETER GatewayInstallDirectory

  The gateway install directory, default install directory will be used if this value is $null.

 .PARAMETER EmailAddress

  The email address.
#>
Function Set-OnPremisesDataGatewayUserAccount(
    [Parameter(Mandatory=$true)]
    [string]$EmailAddress,
    [string]$GatewayInstallDirectory = $null) {
    # Get settings
    If ($GatewayInstallDirectory) {
        $GWDir = $GatewayInstallDirectory
    } else {
        $GWDir = Join-Path $env:ProgramW6432 "\On-premises data gateway"
    }
    
    $configPath = $GWDir + "\Microsoft.PowerBI.DataMovement.GatewayCommon.dll.config"
    $config = [xml](gc $configPath)
    $settings = $config.configuration.applicationSettings.'Microsoft.PowerBI.DataMovement.GatewayCommon.Properties.GatewayCommonSettings'.setting
    $EmailDiscoveryDisable = ($settings | ? { $_.name -eq "EmailDiscoveryDisable" }).value
    $script:RegionSupport = ($settings | ? { $_.name -eq "RegionSupport" }).value
    $script:gsEndpoint = ($settings | ? { $_.name -eq "GlobalServiceEndpoint" }).value

    # Get environment
    If ($EmailDiscoveryDisable) {
        Get-DefaultEnvironment
    } else {
        $script:gsBackendUriOverride = $null
        $r = Get-EmailProperties $EmailAddress
        if (!$r) {
            Write-Warning "Get email properties from global service failed, will use default environment."
            Get-DefaultEnvironment
        }
    }

    if ($script:adResource -eq $null -or $script:gsEndpoint -eq $null) {
        Write-Error "Read AD resource and global service endpoint failed, make sure install gateway first or provide correct install directory!"
        return
    }

    # Get token
    Add-Type -Path $( join-path $GWDir "Microsoft.IdentityModel.Clients.ActiveDirectory.dll")
    Add-Type -Path $( join-path $GWDir "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll")
    Add-Type -Path $( join-path $GWDir "Microsoft.PowerBI.DataMovement.GatewayRegions.dll")
    Add-Type -Path $( join-path $GWDir "Newtonsoft.Json.dll")
    $script:token = Get-Token

    If (!$script:token) {
        Write-Warning "Acquire token failed."
        return
    }

    # Get backend uri
    If ($script:gsBackendUriOverride -ne $null) {
        $script:backendUri = $script:gsBackendUriOverride
    } else {
        $clusterUri = $script:gsEndpoint + "/spglobalservice/GetOrInsertClusterUrisByTenantLocation"
        $gsResponse = Invoke-Webrequest -Uri $clusterUri -Headers @{Authorization = "Bearer " + $token.AccessToken} -Method Put 
        $gsResponse = $gsResponse.Content | ConvertFrom-Json
        $script:backendUri = $gsResponse.FixedClusterUri
    }

    $script:selectedBackend = $script:backendUri
    Write-Host -ForegroundColor Green "Current backend is: " $script:selectedBackend
}

<#
 .SYNOPSIS

  Get token from AD.

 .DESCRIPTION

  Get token from AD.
#>
Function Get-Token(){
    $context=[Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($script:adAuthority);
    $queryParams = "prompt=select_account&msafed=0&login_hint=" + $script:emailAddress
    $userId = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier]::AnyUser
    return $context.AcquireToken($script:adResource, $script:adClientId, $script:adRedirect, 0, $userId, $queryParams)
}

<#
 .SYNOPSIS

  Get gateway regions from CDN.

 .DESCRIPTION

  Get gateway regions from CDN.
#>
Function Get-Regions() {
    $script:allRegions = [Microsoft.PowerBI.DataMovement.GatewayRegions.GatewayRegionConfiguration]::GetRegionsAllowedForTenant($script:backendUri)
}

<#
 .SYNOPSIS

  Get gateway regions.

 .DESCRIPTION

  Get gateway regions allowed for tenant.
#>
Function Get-OnPremisesDataGatewayRegions() {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    If ($script:RegionSupport -ne $true) {
        Write-Warning "Region isn't supported."
        return
    }

    Get-Regions

    If ($script:allRegions.Count) {
        Write-Host -ForegroundColor Green "Available regions:"
        ForEach ($region in $script:allRegions) { Write-Host $region.Region }
    } Else {
        Write-Host -ForegroundColor Green "No region available."
    }
}

<#
 .SYNOPSIS

  Set gateway region.

 .DESCRIPTION

  Set gateway region, will set to default region if this value is $null.

  .PARAMETER Region

  The gateway region.
#>
Function Set-OnPremisesDataGatewayRegion([string]$Region) {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    If ($Region) {
        $selectedRegion = $script:allRegions | ? { $_.Region -eq $Region }

        If (!$selectedRegion) {
            Write-Warning "Invalid region."
            return
        }

        $script:selectedBackend = $selectedRegion.BackendUri.ToString()
    } Else {
        $script:selectedBackend = $script:backendUri
    }

    Write-Host -ForegroundColor Green "Current backend is: " $script:selectedBackend
}

<#
 .SYNOPSIS

  Get gateway clusters.

 .DESCRIPTION

  This function read all gateway clusters owned by the user.
#>
Function Get-OnPremisesDataGatewayClusters(){
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    try {
        $gatewayclusters = Invoke-Webrequest -Uri ($script:selectedBackend + "/unifiedgateway/gatewayclusters") -Headers @{Authorization = "Bearer " + $script:token.AccessToken}
        $gatewayclusters = $gatewayclusters.Content | ConvertFrom-Json

        ForEach ($cluster in $gatewayclusters) {
            $cluster.PSObject.Properties.Remove("annotation")
            $cluster.PSObject.Properties.Remove("publickey")
            $cluster.PSObject.Properties.Remove("keyword")
            $cluster.PSObject.Properties.Remove("metadata")
            $cluster.PSObject.Properties.Remove("gatewayId")
            $cluster = Set-ClusterLoadBalancingType -ClusterObject $cluster

            ForEach ($gw in $cluster.gateways) {
                $gwAnnotation = $gw.gatewayAnnotation | ConvertFrom-Json
                $gw | Add-Member -MemberType NoteProperty -Name gatewayContactInformation -Value ([System.String]::Join(" ", $gwAnnotation.gatewayContactInformation))
                $gw | Add-Member -MemberType NoteProperty -Name gatewayMachine -Value $gwAnnotation.gatewayMachine
                $gw.PSObject.Properties.Remove("gatewayAnnotation")
                $gw.PSObject.Properties.Remove("gatewayStaticCapabilities")
                $gw.PSObject.Properties.Remove("gatewayLoadBalancingSettings")
            }

            $cluster.gateways = $cluster.gateways | ConvertTo-Json
            $cluster.permission = $cluster.permission | ConvertTo-Json
        }

        return $gatewayclusters
    }
    catch {
        Write-WebRequestFailure
    }
}

<#
 .SYNOPSIS

  Get gateway clusters without skipping annotation and static capabilities.

 .DESCRIPTION

  This function read all gateway clusters owned by the user.
#>
Function Get-OnPremisesDataGatewayClustersInternal(){
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    try {
        $gatewayclusters = Invoke-Webrequest -Uri ($script:selectedBackend + "/unifiedgateway/gatewayclusters") -Headers @{Authorization = "Bearer " + $script:token.AccessToken}
        $gatewayclusters = $gatewayclusters.Content | ConvertFrom-Json
        return $gatewayclusters
    }
    catch {
        Write-WebRequestFailure
    }
}

<#
 .SYNOPSIS

  Get gateway status.

 .DESCRIPTION

  This function get gateway status.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER GatewayObjectId

  The gateway objectId.
#>
Function Get-OnPremisesDataGatewayStatus(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [Parameter(Mandatory=$true)]
    [Guid] $GatewayObjectId){
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    try {
        $gatewayStatus = Invoke-Webrequest -Uri ($script:selectedBackend + "/unifiedgateway/gatewayclusters/" + $ClusterObjectId + "/gateways/" + $GatewayObjectId + "/status") -Headers @{Authorization = "Bearer " + $script:token.AccessToken}
        $gatewayStatus = $gatewayStatus.Content | ConvertFrom-Json
        return $gatewayStatus
    }
    catch {
        $response = Get-ResponseFromWebException $_.Exception | ConvertFrom-Json
        If ($response.error.code -eq "DM_GWPipeline_Client_GatewayUnreachable") {
            $gwObj = New-Object -TypeName PSObject -Property ([ordered]@{gatewayStatus = "Unreachable"; gatewayVersion = "Unknown"; gatewayUpgradeState = "Unknown"})
            return $gwObj
        } Else {
            Write-Warning $_.Exception.Message
            If ($responseBody) { Write-Warning $responseBody }
        }
    }
}

<#
 .SYNOPSIS

  Set gateway info.

 .DESCRIPTION

  This function set gateway info and return the updated info, note it won't update the field if it's value is null.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER GatewayObjectId

  The gateway objectId.

 .PARAMETER MemberStatus

  The cluster member status.
 
 .PARAMETER GatewayContactInformation

  The gateway contact information.

 .PARAMETER Name

  The gateway name.
#>
Function Set-OnPremisesDataGateway(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [Parameter(Mandatory=$true)]
    [Guid] $GatewayObjectId,
    [ValidateSet("None","Enabled")]
    [string] $MemberStatus = $script:nullString,
    [string] $GatewayContactInformation = $script:nullString,
    [string] $Name = $script:nullString) {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    $request = @{}

    If ($MemberStatus -ne $script:nullString) { $request.Add("clusterMemberStatus", $MemberStatus)}

    If ($Name -ne $script:nullString) {
        If ($Name.Trim() -eq '') {
            Write-Warning 'Gateway name cannot be empty.'
            return
        }

        $request.Add("gatewayName",$Name)
    }

    If ($GatewayContactInformation -ne $script:nullString) {
        $annotation = Create-GatewayAnnotation $ClusterObjectId $GatewayObjectId $GatewayContactInformation
        If ($annotation) {
            $request.Add("gatewayAnnotation",$annotation)
        } Else {
            return
        }
    }    

    $json = $request | ConvertTo-Json
    $uri = $script:selectedBackend + "/unifiedgateway/gatewayclusters/" + $ClusterObjectId + "/gateways/" + $GatewayObjectId

    try {
        $response = Invoke-Webrequest -Uri $uri -Headers @{Authorization = "Bearer " + $script:token.AccessToken} -Method Patch -Body $json -ContentType 'application/json'
        $response = $response.Content | ConvertFrom-Json
        $response.PSObject.Properties.Remove("gatewayStaticCapabilities")
        $response.PSObject.Properties.Remove("gatewayStatus")

        #Extract contact info and machine from annotation
        $gwAnnotation = $response.gatewayAnnotation | ConvertFrom-Json
        $response | Add-Member -MemberType NoteProperty -Name gatewayContactInformation -Value ([System.String]::Join(" ", $gwAnnotation.gatewayContactInformation))
        $response | Add-Member -MemberType NoteProperty -Name gatewayMachine -Value $gwAnnotation.gatewayMachine
        $response.PSObject.Properties.Remove("gatewayAnnotation")
        $response.PSObject.Properties.Remove("gatewayLoadBalancingSettings")
        return $response
    }
    catch {
        Write-WebRequestFailure
    }
}

<#
 .SYNOPSIS

  Get gateway.

 .DESCRIPTION

  This function get gateway by searching cluster and gateway in all clusters.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER GatewayObjectId

  The gateway objectId.
#>
Function Get-OnPremisesDataGateway(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [Parameter(Mandatory=$true)]
    [Guid] $GatewayObjectId) {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    $clusters = Get-OnPremisesDataGatewayClustersInternal
    $cluster = $clusters | Where-Object { $_.objectId -eq $ClusterObjectId }

    If (!$cluster) {
        Write-Host -ForegroundColor Red "Invalid cluster object Id"
        return
    }

    $gateway = $cluster.gateways | Where-Object { $_.gatewayObjectId -eq $GatewayObjectId }

    If (!$gateway) {
        Write-Host -ForegroundColor Red "Invalid gateway object Id"
        return
    }

    return $gateway
}

<#
 .SYNOPSIS

  Create gateway annotation.

 .DESCRIPTION

  This function get gateway annotation then fill with given contact information and machine name.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER GatewayObjectId

  The gateway objectId.

 .PARAMETER GatewayContactInformation

  The gateway contact information.
#>
Function Create-GatewayAnnotation(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [Parameter(Mandatory=$true)]
    [Guid] $GatewayObjectId,
    [string] $GatewayContactInformation = $script:nullString) {
    $gateway = Get-OnPremisesDataGateway $ClusterObjectId $GatewayObjectId

    If ($gateway) {
        $gwAnnotation = $gateway.gatewayAnnotation | ConvertFrom-Json
            
        If ($GatewayContactInformation -ne $script:nullString) {
            $gwAnnotation.gatewayContactInformation = @($GatewayContactInformation)
        }

        return $gwAnnotation | ConvertTo-Json
    }
}


<#
 .SYNOPSIS

  Delete gateway.

 .DESCRIPTION

  This function delete gateway, note it will return success for nonexistent gateway.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER GatewayObjectId

  The gateway objectId.
#>
Function Remove-OnPremisesDataGateway(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [Parameter(Mandatory=$true)]
    [Guid] $GatewayObjectId) {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    try {
        $uri = $script:selectedBackend + "/unifiedgateway/gatewayclusters/" + $ClusterObjectId + "/gateways/" + $GatewayObjectId
        $response = Invoke-Webrequest -Uri $uri -Headers @{Authorization = "Bearer " + $script:token.AccessToken} -Method Delete
        $response = $response.Content | ConvertFrom-Json
        return $response
    }
    catch {
        Write-WebRequestFailure
    }
}

<#
 .SYNOPSIS

  Set gateway cluster info.

 .DESCRIPTION

  This function set gateway cluster info and return the updated info, note it won't update the field if it's value is null.

 .PARAMETER ClusterObjectId

  The cluster object Id.

 .PARAMETER Name

  The cluster name.

 .PARAMETER Description

  The cluster description.
#>
Function Set-OnPremisesDataGatewayCluster(
    [Parameter(Mandatory=$true)]
    [Guid] $ClusterObjectId,
    [string] $Name = $script:nullString,
    [string] $Description = $script:nullString,
    [ValidateSet("Failover","Random")]
    [string] $LoadBalancingType = $script:nullString) {
    If (!$script:selectedBackend) {
        Write-Warning "Please log in first."
        return
    }

    $request = @{}
    
    If ($Name -ne $script:nullString) {
        If ($Name.Trim() -eq '') {
            Write-Warning 'Cluster name cannot be empty.'
            return
        }

        $request.Add("name",$Name)
    }

    If ($Description -ne $script:nullString) { $request.Add("description",$Description) }

    If ($LoadBalancingType -ne $script:nullString) {
        $loadBalancingClusterSettings = @{}
        $type = $LoadBalancingType -as [LoadBalancingType]
        $loadBalancingClusterSettings.Add("selector", [int]$type)
        $loadBalancingClusterSettingsJson = $loadBalancingClusterSettings | ConvertTo-Json -Compress
        $request.Add("loadBalancingSettings", $loadBalancingClusterSettingsJson)
    }

    $json = $request | ConvertTo-Json
    $uri = $script:selectedBackend + "/unifiedgateway/gatewayclusters/" + $ClusterObjectId

    try {
        $response = Invoke-Webrequest -Uri $uri -Headers @{Authorization = "Bearer " + $script:token.AccessToken} -Method Patch -Body $json -ContentType 'application/json'
        $response = $response.Content | ConvertFrom-Json
        $response.PSObject.Properties.Remove("annotation")
        $response = Set-ClusterLoadBalancingType -ClusterObject $response
        return $response
    }
    catch {
        Write-WebRequestFailure
    }
}

<#
 .SYNOPSIS

  Get all gateway info in cluster.

 .DESCRIPTION

  This function list all gateways in cluster.

 .PARAMETER ClusterObjectId

  The cluster object Id.
#>
Function Get-OnPremisesDataClusterGateways(
    [Parameter(Mandatory=$true)][Guid] $ClusterObjectId) {
    $clusters = Get-OnPremisesDataGatewayClustersInternal

    If ($clusters -eq $null) { return }

    $cluster = $clusters | Where-Object { $_.objectId -eq $ClusterObjectId }
    $gateways = New-Object System.Collections.ArrayList

    If ($cluster -eq $null) {
        Write-Host -ForegroundColor Red "Invalid cluster object Id"
        return
    }

    ForEach ($gateway in $cluster.gateways) {
        $gwStatus = Get-OnPremisesDataGatewayStatus $cluster.objectId $gateway.gatewayObjectId
        $gwAnnotation = $gateway.gatewayAnnotation | ConvertFrom-Json
        $gwObj = New-Object PSObject -Property (
            [ordered]@{
                gatewayId = $gateway.gatewayId;
                gatewayObjectId = $gateway.gatewayObjectId;
                gatewayName = $gateway.gatewayName;
                isAnchorGateway = $gateway.isAnchorGateway;
                gatewayStatus = $gwStatus.gatewayStatus;
                gatewayVersion = $gwStatus.gatewayVersion;
                gatewayUpgradeState = $gwStatus.gatewayUpgradeState;
                gatewayClusterStatus = $gateway.gatewayClusterStatus;
                gatewayMachine = $gwAnnotation.gatewayMachine;
                })
        $gateways.Add($gwObj) > $null
    }
    
    return $gateways
}


<#
 .SYNOPSIS

  Set load balancing type for cluster object.

 .DESCRIPTION

  This function sets load balancing type for cluster object.

 .PARAMETER ClusterObject

  The cluster object.
#>
Function Set-ClusterLoadBalancingType(
    [Parameter(Mandatory=$true)][PSObject] $ClusterObject) {
        $loadBalancingType = [LoadBalancingType]::Failover

        If ($ClusterObject.loadBalancingSettings) {
            $loadBalancingSettings = $ClusterObject.loadBalancingSettings | ConvertFrom-Json
            $type = $loadBalancingSettings.selector -as [LoadBalancingType]
        
            If ($type -is [LoadBalancingType]) {
                $loadBalancingType = $type
            }
        }

        $ClusterObject | Add-Member -Name loadBalancingType -Value $loadBalancingType -MemberType NoteProperty
        $ClusterObject.PSObject.Properties.Remove("loadBalancingSettings")
        return $ClusterObject
}

Set-Alias Login-OnPremisesDataGateway Set-OnPremisesDataGatewayUserAccount
Set-Alias Logout-OnPremisesDataGateway Remove-OnPremisesDataGatewayUserAccount
Export-ModuleMember -Function Get-OnPremisesDataGatewayClusters
Export-ModuleMember -Function Get-OnPremisesDataGatewayStatus
Export-ModuleMember -Function Set-OnPremisesDataGateway
Export-ModuleMember -Function Remove-OnPremisesDataGateway
Export-ModuleMember -Function Set-OnPremisesDataGatewayCluster
Export-modulemember -Function Get-OnPremisesDataGatewayRegions
Export-ModuleMember -Function Set-OnPremisesDataGatewayRegion
Export-ModuleMember -Function Set-OnPremisesDataGatewayUserAccount
Export-ModuleMember -Function Remove-OnPremisesDataGatewayUserAccount
Export-ModuleMember -Function Get-OnPremisesDataClusterGateways
Export-ModuleMember -Alias Login-OnPremisesDataGateway
Export-ModuleMember -Alias Logout-OnPremisesDataGateway