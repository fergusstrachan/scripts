#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Policy Viewer
    Single-pane view of every setting applied to a device or user, grouped by policy.

.NOTES
    Required Graph Permissions (delegated):
        DeviceManagementConfiguration.Read.All
        DeviceManagementManagedDevices.Read.All
        DeviceManagementServiceConfig.Read.All
        Group.Read.All
        User.Read.All
        Device.Read.All

    Required Module:
        Microsoft.Graph.Authentication
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

    Layout:
        Left  : search results
        Right : single grid — policy header rows (dark blue) + setting rows beneath each
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

#region ── Module ─────────────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host 'Installing Microsoft.Graph.Authentication...' -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
#endregion

#region ── Assemblies ─────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
#endregion

#region ── Script-scope state ─────────────────────────────────────────────────
$script:IsConnected = $false
$script:SearchItems = @()
$script:PolicyData = @()
$script:Form = $null
$script:TxtSearch = $null
$script:RbDevice = $null
$script:RbUser = $null
$script:BtnSearch = $null
$script:BtnConnect = $null
$script:BtnExport = $null
$script:ListResults = $null
$script:LblStatus = $null
$script:DgvMain = $null   # the single all-settings grid
$script:LblPane = $null   # header label above the grid
$script:Worker = $null   # busy flag: set to "busy" while loading
$script:ToolTip = $null   # ToolTip control for setting descriptions
$script:CmbDevice = $null   # device filter combobox (user mode)
$script:PnlFilter = $null   # panel containing device filter
$script:UserDevices = @()    # managed devices for current user
#endregion

#region ── Colours (used by row painter) ─────────────────────────────────────
$script:ColPolicyHeader = [System.Drawing.Color]::FromArgb(0, 100, 180)
$script:ColPolicyText = [System.Drawing.Color]::White
$script:ColSettingAlt = [System.Drawing.Color]::FromArgb(245, 248, 255)
$script:ColExcluded = [System.Drawing.Color]::FromArgb(255, 220, 220)
$script:ColExcludedText = [System.Drawing.Color]::DarkRed
$script:FontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:FontNormal = New-Object System.Drawing.Font('Segoe UI', 9)
#endregion

#region ── Policy Type Definitions ───────────────────────────────────────────
$script:PolicyTypes = @(
    [PSCustomObject]@{ Label = 'Config Policies (Settings Catalogue)'; Path = 'beta/deviceManagement/configurationPolicies'; NameProp = 'name'; SettingsType = 'SettingsCatalogue' }
    [PSCustomObject]@{ Label = 'Device Configurations'; Path = 'v1.0/deviceManagement/deviceConfigurations'; NameProp = 'displayName'; SettingsType = 'DeviceConfig' }
    [PSCustomObject]@{ Label = 'Compliance Policies'; Path = 'v1.0/deviceManagement/deviceCompliancePolicies'; NameProp = 'displayName'; SettingsType = 'Compliance' }
    [PSCustomObject]@{ Label = 'GP/ADMX Configurations'; Path = 'v1.0/deviceManagement/groupPolicyConfigurations'; NameProp = 'displayName'; SettingsType = 'GroupPolicy' }
    [PSCustomObject]@{ Label = 'Endpoint Security'; Path = 'beta/deviceManagement/intents'; NameProp = 'displayName'; SettingsType = 'Intent' }
    [PSCustomObject]@{ Label = 'Windows Update Rings'; Path = 'v1.0/deviceManagement/deviceUpdatePolicies'; NameProp = 'displayName'; SettingsType = 'Inline' }
    [PSCustomObject]@{ Label = 'Feature Update Profiles'; Path = 'beta/deviceManagement/windowsFeatureUpdateProfiles'; NameProp = 'displayName'; SettingsType = 'Inline' }
    [PSCustomObject]@{ Label = 'Quality Update Profiles'; Path = 'beta/deviceManagement/windowsQualityUpdatePolicies'; NameProp = 'displayName'; SettingsType = 'Inline' }
    [PSCustomObject]@{ Label = 'Driver Update Profiles'; Path = 'beta/deviceManagement/windowsDriverUpdateProfiles'; NameProp = 'displayName'; SettingsType = 'Inline' }
    [PSCustomObject]@{ Label = 'App Protection Policies'; Path = 'v1.0/deviceAppManagement/managedAppPolicies'; NameProp = 'displayName'; SettingsType = 'Inline' }
)
#endregion

#region ── Graph Helpers ──────────────────────────────────────────────────────
function Invoke-GraphGet ([string]$Uri) {
    $results = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject
        if ($response.value) { foreach ($v in $response.value) { $results.Add($v) } }
        $nextLink = $response.'@odata.nextLink'
    } while ($nextLink)
    return $results
}

function Connect-ToGraph {
    Connect-MgGraph -Scopes @(
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementServiceConfig.Read.All'
        'Group.Read.All'
        'User.Read.All'
        'Device.Read.All'
    ) -NoWelcome
}

function Search-IntuneDevice ([string]$Name) {
    $enc = [Uri]::EscapeDataString($Name)
    Invoke-GraphGet "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=contains(deviceName,'$enc')&`$select=id,deviceName,operatingSystem,userPrincipalName,azureADDeviceId"
}

function Search-EntraUser ([string]$Name) {
    $enc = [Uri]::EscapeDataString($Name)
    Invoke-GraphGet "https://graph.microsoft.com/v1.0/users?`$filter=startsWith(displayName,'$enc') or startsWith(userPrincipalName,'$enc')&`$select=id,displayName,userPrincipalName"
}

function Get-EntraDeviceId ([string]$AzureAdDeviceId) {
    (Invoke-GraphGet "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$AzureAdDeviceId'&`$select=id") | Select-Object -First 1
}

function Get-GroupMemberships ([string]$ObjectType, [string]$ObjectId) {
    try { Invoke-GraphGet "https://graph.microsoft.com/v1.0/$ObjectType/$ObjectId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName" }
    catch { Invoke-GraphGet "https://graph.microsoft.com/v1.0/$ObjectType/$ObjectId/memberOf/microsoft.graph.group?`$select=id,displayName" }
}

function Get-UserManagedDevices ([string]$UserId, [string]$UPN) {
    # Try UPN filter first (most reliable), fall back to userId filter
    if ($UPN) {
        $enc = [Uri]::EscapeDataString($UPN)
        try {
            $result = Invoke-GraphGet "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=userPrincipalName eq '$enc'&`$select=id,deviceName,operatingSystem,azureADDeviceId,userPrincipalName"
            if ($result) { return $result }
        }
        catch {}
    }
    # Fallback: userId filter on beta endpoint
    $enc2 = [Uri]::EscapeDataString($UserId)
    Invoke-GraphGet "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userId eq '$enc2'&`$select=id,deviceName,operatingSystem,azureADDeviceId,userPrincipalName"
}
#endregion

#region ── Policy Assignment Logic ───────────────────────────────────────────
function Get-AppliedPolicies ([string[]]$GroupIds, [bool]$IsDevice, [bool]$IsUser, [string]$DeviceOS = '') {

    # When in device mode, restrict to policy types relevant for that OS
    # DeviceOS values from Intune: Windows, iOS, Android, macOS, AndroidForWork etc.
    $activePolicyTypes = $script:PolicyTypes
    if ($IsDevice -and -not $IsUser -and $DeviceOS) {
        $os = $DeviceOS.ToLower()
        $activePolicyTypes = $script:PolicyTypes | Where-Object {
            $label = $_.Label.ToLower()
            if ($os -match 'windows') {
                # Exclude iOS/Android-specific types
                $label -notmatch 'ios|android|app protection'
            }
            elseif ($os -match 'ios') {
                $label -notmatch 'windows|android|gp/admx|update ring|feature update|quality update|driver update'
            }
            elseif ($os -match 'android') {
                $label -notmatch 'windows|ios|gp/admx|update ring|feature update|quality update|driver update'
            }
            elseif ($os -match 'macos') {
                $label -notmatch 'windows|ios|android|gp/admx|update ring|feature update|quality update|driver update'
            }
            else {
                $true  # unknown OS - show everything
            }
        }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pt in $activePolicyTypes) {
        try { $policies = Invoke-GraphGet "https://graph.microsoft.com/$($pt.Path)?`$expand=assignments" }
        catch { continue }

        foreach ($policy in $policies) {
            $policyName = if ($policy.($pt.NameProp)) { $policy.($pt.NameProp) } else { $policy.id }
            if (-not $policy.assignments) { continue }

            # Per-policy OS filtering when in device mode
            if ($IsDevice -and -not $IsUser -and $DeviceOS) {
                $os = $DeviceOS.ToLower()

                # Settings Catalogue has a 'platforms' property: windows10, iOS, android, macOS etc.
                if ($policy.platforms) {
                    $pPlatform = $policy.platforms.ToLower()
                    $skip = $false
                    if ($os -match 'windows' -and $pPlatform -notmatch 'windows') { $skip = $true }
                    if ($os -match '^ios' -and $pPlatform -notmatch 'ios') { $skip = $true }
                    if ($os -match 'android' -and $pPlatform -notmatch 'android') { $skip = $true }
                    if ($os -match 'macos' -and $pPlatform -notmatch 'mac') { $skip = $true }
                    if ($skip) { continue }
                }

                # Device Configurations and Compliance Policies encode OS in @odata.type
                # e.g. #microsoft.graph.iosCompliancePolicy, #microsoft.graph.androidCompliancePolicy
                # #microsoft.graph.windows10CompliancePolicy, #microsoft.graph.macOSCompliancePolicy
                $odType = $policy.'@odata.type'
                if ($odType) {
                    $odType = $odType.ToLower()
                    $skip = $false
                    if ($os -match 'windows' -and $odType -match 'ios|android(?!forwork)|^.*android') { $skip = $true }
                    if ($os -match '^ios' -and $odType -match 'windows|android|macos') { $skip = $true }
                    if ($os -match 'android' -and $odType -match 'windows|^.*ios|macos') { $skip = $true }
                    if ($os -match 'macos' -and $odType -match 'windows|ios|android') { $skip = $true }
                    if ($skip) { continue }
                }
            }

            $matchReason = $null
            foreach ($assignment in $policy.assignments) {
                $target = $assignment.target
                $odataType = $target.'@odata.type'
                switch ($odataType) {
                    '#microsoft.graph.allDevicesAssignmentTarget' { if ($IsDevice) { $matchReason = 'All Devices'; break } }
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { if ($IsUser) { $matchReason = 'All Users'; break } }
                    '#microsoft.graph.groupAssignmentTarget' { if ($GroupIds -contains $target.groupId) { $matchReason = 'Group (Included)'; break } }
                    '#microsoft.graph.exclusionGroupAssignmentTarget' { if ($GroupIds -contains $target.groupId) { $matchReason = 'Group (EXCLUDED)'; break } }
                }
                if ($matchReason) { break }
            }

            if ($matchReason) {
                $results.Add([PSCustomObject]@{
                        PolicyType   = $pt.Label
                        PolicyName   = $policyName
                        Assignment   = $matchReason
                        PolicyId     = $policy.id
                        SettingsType = $pt.SettingsType
                    })
            }
        }
    }
    return $results
}
#endregion

#region ── Settings Retrieval ─────────────────────────────────────────────────
function Get-SettingInstanceValue ($Instance) {
    if ($null -eq $Instance) { return '(null)' }
    switch -Wildcard ($Instance.'@odata.type') {
        '*simpleSettingInstance' { return "$($Instance.simpleSettingValue.value)" }
        '*choiceSettingInstance' { return ($Instance.choiceSettingValue.value -replace '^.*_(?=[^_]+$)', [string]::Empty) }
        '*simpleSettingCollectionInstance' { return ($Instance.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join '; ' }
        '*choiceSettingCollectionInstance' { return ($Instance.choiceSettingCollectionValue | ForEach-Object { ($_.value -replace '^.*_(?=[^_]+$)', [string]::Empty) }) -join '; ' }
        '*groupSettingCollectionInstance' { return '(group collection)' }
        '*groupSettingInstance' { return '(group setting)' }
        default { return "$($Instance.'@odata.type')" }
    }
}

function Flatten-Object ($Obj, [string]$Prefix = '') {
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($null -eq $Obj) { return $rows }
    foreach ($prop in $Obj.PSObject.Properties) {
        $key = $prop.Name
        if ($key -like '@*') { continue }
        $fullKey = if ($Prefix) { "$Prefix > $key" } else { $key }
        $val = $prop.Value
        if ($null -eq $val) {
            $rows.Add([PSCustomObject]@{ Setting = $fullKey; Value = '(null)'; Description = '' })
        }
        elseif ($val -is [System.Management.Automation.PSCustomObject]) {
            foreach ($n in (Flatten-Object -Obj $val -Prefix $fullKey)) { $rows.Add($n) }
        }
        elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
            $arr = @($val)
            if ($arr.Count -eq 0) {
                $rows.Add([PSCustomObject]@{ Setting = $fullKey; Value = '(empty)'; Description = '' })
            }
            elseif ($arr[0] -is [System.Management.Automation.PSCustomObject]) {
                for ($i = 0; $i -lt $arr.Count; $i++) {
                    foreach ($n in (Flatten-Object -Obj $arr[$i] -Prefix "$fullKey[$i]")) { $rows.Add($n) }
                }
            }
            else {
                $rows.Add([PSCustomObject]@{ Setting = $fullKey; Value = ($arr -join '; '); Description = '' })
            }
        }
        else {
            $rows.Add([PSCustomObject]@{ Setting = $fullKey; Value = "$val"; Description = '' })
        }
    }
    return $rows
}

$script:InlineExclude = @('id', 'displayName', 'description', 'createdDateTime', 'lastModifiedDateTime',
    'version', 'roleScopeTagIds', '@odata.type', '@odata.context',
    'assignments', 'scheduledActionsForRule', 'supportsScopeTags')

function Get-PolicySettings ([string]$PolicyId, [string]$SettingsType) {
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    switch ($SettingsType) {

        'SettingsCatalogue' {
            try { $settings = Invoke-GraphGet "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/settings?`$expand=settingDefinitions&`$top=1000" }
            catch { return $rows }
            foreach ($s in $settings) {
                $inst = $s.settingInstance
                if (-not $inst) { continue }
                $defId = $inst.settingDefinitionId
                $defName = $defId
                if ($s.settingDefinitions) {
                    $def = $s.settingDefinitions | Where-Object { $_.id -eq $defId } | Select-Object -First 1
                    if ($def -and $def.displayName) { $defName = $def.displayName }
                }
                $desc = ''
                if ($s.settingDefinitions) {
                    $def2 = $s.settingDefinitions | Where-Object { $_.id -eq $defId } | Select-Object -First 1
                    if ($def2 -and $def2.description) { $desc = $def2.description }
                }
                $rows.Add([PSCustomObject]@{ Setting = $defName; Value = (Get-SettingInstanceValue $inst); Description = $desc })
            }
        }

        'DeviceConfig' {
            try { $obj = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId" -OutputType PSObject }
            catch { return $rows }
            foreach ($prop in $obj.PSObject.Properties) {
                if ($script:InlineExclude -contains $prop.Name) { continue }
                if ($prop.Name -like '@*') { continue }
                $val = $prop.Value
                if ($null -eq $val) { continue }
                if ($val -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($n in (Flatten-Object -Obj $val -Prefix $prop.Name)) { $rows.Add($n) }
                }
                elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $arr = @($val)
                    if ($arr.Count -eq 0) { continue }
                    if ($arr[0] -is [System.Management.Automation.PSCustomObject]) {
                        for ($i = 0; $i -lt $arr.Count; $i++) {
                            foreach ($n in (Flatten-Object -Obj $arr[$i] -Prefix "$($prop.Name)[$i]")) { $rows.Add($n) }
                        }
                    }
                    else {
                        $rows.Add([PSCustomObject]@{ Setting = $prop.Name; Value = ($arr -join '; '); Description = '' })
                    }
                }
                else {
                    $rows.Add([PSCustomObject]@{ Setting = $prop.Name; Value = "$val"; Description = '' })
                }
            }
        }

        'Compliance' {
            try { $obj = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId" -OutputType PSObject }
            catch { return $rows }
            foreach ($prop in $obj.PSObject.Properties) {
                if ($script:InlineExclude -contains $prop.Name) { continue }
                if ($prop.Name -like '@*') { continue }
                $val = $prop.Value
                if ($null -eq $val) { continue }
                if ($val -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($n in (Flatten-Object -Obj $val -Prefix $prop.Name)) { $rows.Add($n) }
                }
                else {
                    $rows.Add([PSCustomObject]@{ Setting = $prop.Name; Value = "$val"; Description = '' })
                }
            }
        }

        'GroupPolicy' {
            try { $defVals = Invoke-GraphGet "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$PolicyId')/definitionValues?`$expand=definition,presentationValues" }
            catch { return $rows }
            foreach ($dv in $defVals) {
                $name = if ($dv.definition -and $dv.definition.displayName) { $dv.definition.displayName } else { $dv.id }
                $enabled = if ($dv.enabled -eq $true) { 'Enabled' } elseif ($dv.enabled -eq $false) { 'Disabled' } else { "$($dv.enabled)" }
                if ($dv.presentationValues -and $dv.presentationValues.Count -gt 0) {
                    foreach ($pv in $dv.presentationValues) {
                        $pvVal = if ($null -ne $pv.value) { "$($pv.value)" } elseif ($pv.values) { $pv.values -join '; ' } else { $enabled }
                        $rows.Add([PSCustomObject]@{ Setting = $name; Value = "$pvVal  [$enabled]"; Description = '' })
                    }
                }
                else {
                    $rows.Add([PSCustomObject]@{ Setting = $name; Value = $enabled; Description = '' })
                }
            }
        }

        'Intent' {
            try { $settings = Invoke-GraphGet "https://graph.microsoft.com/beta/deviceManagement/intents/$PolicyId/settings" }
            catch { return $rows }
            foreach ($s in $settings) {
                $rows.Add([PSCustomObject]@{
                        Setting     = ($s.definitionId -replace '^.*_', [string]::Empty)
                        Value       = if ($null -ne $s.value) { "$($s.value)" } else { '(not set)' }
                        Description = ''
                    })
            }
        }

        'Inline' {
            # Try each possible endpoint until one works
            $endpoints = @(
                "https://graph.microsoft.com/v1.0/deviceManagement/deviceUpdatePolicies/$PolicyId"
                "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$PolicyId"
                "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies/$PolicyId"
                "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$PolicyId"
                "https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies/$PolicyId"
            )
            $obj = $null
            foreach ($ep in $endpoints) {
                try { $obj = Invoke-MgGraphRequest -Method GET -Uri $ep -OutputType PSObject; break } catch {}
            }
            if ($null -eq $obj) { return $rows }
            foreach ($prop in $obj.PSObject.Properties) {
                if ($script:InlineExclude -contains $prop.Name) { continue }
                if ($prop.Name -like '@*') { continue }
                $val = $prop.Value
                if ($null -eq $val) { continue }
                if ($val -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($n in (Flatten-Object -Obj $val -Prefix $prop.Name)) { $rows.Add($n) }
                }
                elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $arr = @($val)
                    if ($arr.Count -gt 0) {
                        $rows.Add([PSCustomObject]@{ Setting = $prop.Name; Value = ($arr -join '; '); Description = '' })
                    }
                }
                else {
                    $rows.Add([PSCustomObject]@{ Setting = $prop.Name; Value = "$val"; Description = '' })
                }
            }
        }
    }
    return $rows
}
#endregion

#region ── Main load logic ────────────────────────────────────────────────────
function Invoke-Connect {
    $script:LblStatus.Text = 'Connecting to Microsoft Graph...'
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Connect-ToGraph
        $script:IsConnected = $true
        $ctx = Get-MgContext
        $script:LblStatus.Text = "Connected as: $($ctx.Account)"
        $script:BtnConnect.Text = 'Connected'
        $script:BtnConnect.BackColor = [System.Drawing.Color]::FromArgb(80, 200, 100)
        $script:BtnConnect.ForeColor = [System.Drawing.Color]::White
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Connection failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error')
        $script:LblStatus.Text = 'Connection failed.'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Invoke-Search {
    if (-not $script:IsConnected) {
        [System.Windows.Forms.MessageBox]::Show('Please connect to Microsoft Graph first.', 'Not Connected', 'OK', 'Warning')
        return
    }
    $query = $script:TxtSearch.Text.Trim()
    if ($query.Length -lt 2) {
        [System.Windows.Forms.MessageBox]::Show('Enter at least 2 characters.', 'Search', 'OK', 'Information')
        return
    }
    $script:ListResults.Items.Clear()
    $script:DgvMain.DataSource = $null
    $script:SearchItems = @()
    $script:PolicyData = @()
    $script:UserDevices = @()
    $script:BtnExport.Enabled = $false
    $script:CmbDevice.Items.Clear()
    $script:CmbDevice.Items.Add('User policies (no device filter)') | Out-Null
    $script:CmbDevice.SelectedIndex = 0
    $script:PnlFilter.Visible = $false
    $script:LblPane.Text = 'Select a device or user from the left, then choose a view from the dropdown'

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $script:LblStatus.Text = 'Searching...'
    $script:Form.Refresh()
    try {
        if ($script:RbDevice.Checked) {
            $items = @(Search-IntuneDevice -Name $query)
            foreach ($item in $items) {
                $script:ListResults.Items.Add("$($item.deviceName)  [$($item.operatingSystem)]  ($($item.userPrincipalName))") | Out-Null
                $script:SearchItems += [PSCustomObject]@{ Object = $item; Type = 'Device' }
            }
        }
        else {
            $items = @(Search-EntraUser -Name $query)
            foreach ($item in $items) {
                $script:ListResults.Items.Add("$($item.displayName)  ($($item.userPrincipalName))") | Out-Null
                $script:SearchItems += [PSCustomObject]@{ Object = $item; Type = 'User'; UserId = $item.id; UPN = $item.userPrincipalName }
            }
        }
        $script:LblStatus.Text = if ($items.Count -eq 0) { 'No results found.' } elseif ($script:RbUser.Checked) { "$($items.Count) result(s) found — select a user, then choose a view from the dropdown" } else { "$($items.Count) result(s) found — select one to load settings" }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Search error:`n$($_.Exception.Message)", 'Error', 'OK', 'Error')
        $script:LblStatus.Text = 'Search failed.'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Invoke-LoadAll {
    param([switch]$FromDeviceFilter)

    $idx = $script:ListResults.SelectedIndex
    if ($idx -lt 0 -or $idx -ge $script:SearchItems.Count) { return }
    if ($script:Worker -eq 'busy') { return }

    $selected = $script:SearchItems[$idx]
    $obj = $selected.Object
    $type = $selected.Type
    $isDevice = ($type -eq 'Device')
    $isUser = ($type -eq 'User')

    # --- When a user is first selected, fetch their devices and populate the combobox ---
    if ($isUser -and -not $FromDeviceFilter) {
        $script:PnlFilter.Visible = $false
        $script:CmbDevice.Items.Clear()
        $script:CmbDevice.Items.Add('User policies (no device filter)') | Out-Null
        $script:CmbDevice.SelectedIndex = 0
        $script:LblPane.Text = "Fetching devices for $($obj.displayName) ..."
        $script:LblStatus.Text = 'Fetching enrolled devices...'
        $script:Form.Refresh()
        try {
            $upn = if ($selected.UPN) { $selected.UPN } else { $obj.userPrincipalName }
            $script:UserDevices = @(Get-UserManagedDevices -UserId $obj.id -UPN $upn)
            if ($script:UserDevices.Count -gt 0) {
                # Temporarily remove event handler to prevent re-fire while populating
                $script:CmbDevice.remove_SelectedIndexChanged({ Invoke-LoadAll -FromDeviceFilter })
                foreach ($d in $script:UserDevices) {
                    $script:CmbDevice.Items.Add("$($d.deviceName)  [$($d.operatingSystem)]") | Out-Null
                }
                $script:CmbDevice.SelectedIndex = 0
                $script:CmbDevice.add_SelectedIndexChanged({ Invoke-LoadAll -FromDeviceFilter })
                $script:PnlFilter.Visible = $true
            }
        }
        catch {
            $script:LblStatus.Text = "Could not fetch devices: $($_.Exception.Message)"
        }

        # Show prompt and wait for user to pick from dropdown — don't auto-load
        $devCount = $script:UserDevices.Count
        if ($devCount -gt 0) {
            $script:LblPane.Text = "Select a view from the dropdown above, or choose '(User policies only)'"
            $script:LblStatus.Text = "Found $devCount device(s) for $($obj.displayName) — choose from the dropdown to load settings"
        }
        else {
            $script:LblPane.Text = "No enrolled devices found — select '(User policies only)' to load user policies"
            $script:LblStatus.Text = "No enrolled devices found for $($obj.displayName)"
        }
        return
    }

    # Determine target label and extra device context
    $extraDeviceId = $null   # azureADDeviceId of the selected device filter (if any)
    $deviceLabel = [string]::Empty

    $extraDeviceOS = [string]::Empty
    if ($isUser -and $script:CmbDevice.SelectedIndex -gt 0) {
        $devObj = $script:UserDevices[$script:CmbDevice.SelectedIndex - 1]
        $extraDeviceId = $devObj.azureADDeviceId
        $extraDeviceOS = $devObj.operatingSystem
        $deviceLabel = " — Device policies only: $($devObj.deviceName)  [$($devObj.operatingSystem)]"
    }

    $targetLabel = if ($isDevice) { "Device: $($obj.deviceName)" } else { "User: $($obj.displayName)$deviceLabel" }
    $effectiveOS = if ($isDevice) { $obj.operatingSystem } elseif ($extraDeviceOS) { $extraDeviceOS } else { [string]::Empty }

    $script:Worker = 'busy'
    $script:DgvMain.DataSource = $null
    $script:PolicyData = @()
    $script:BtnExport.Enabled = $false
    $script:BtnSearch.Enabled = $false
    $script:ListResults.Enabled = $false
    $script:CmbDevice.Enabled = $false
    $script:LblPane.Text = "Loading policies for $targetLabel ..."
    $script:LblStatus.Text = 'Resolving group memberships...'
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $groupIds = [System.Collections.Generic.List[string]]::new()
        $resolveUser = $isUser -and ($null -eq $extraDeviceId)   # user-only: no device selected
        $resolveDevice = $isDevice -or ($null -ne $extraDeviceId)  # direct device OR device filter

        # --- User groups (only when NOT filtering by a specific device) ---
        if ($resolveUser) {
            $userGroups = @(Get-GroupMemberships -ObjectType 'users' -ObjectId $obj.id)
            foreach ($g in $userGroups) { $groupIds.Add($g.id) }
        }

        # --- Device groups ---
        if ($isDevice) {
            $entraDevice = Get-EntraDeviceId -AzureAdDeviceId $obj.azureADDeviceId
            if ($entraDevice) {
                $devGroups = @(Get-GroupMemberships -ObjectType 'devices' -ObjectId $entraDevice.id)
                foreach ($g in $devGroups) { if (-not $groupIds.Contains($g.id)) { $groupIds.Add($g.id) } }
            }
        }
        elseif ($extraDeviceId) {
            # Device selected from user dropdown — resolve only the device's groups
            $entraDevice = Get-EntraDeviceId -AzureAdDeviceId $extraDeviceId
            if ($entraDevice) {
                $devGroups = @(Get-GroupMemberships -ObjectType 'devices' -ObjectId $entraDevice.id)
                foreach ($g in $devGroups) { if (-not $groupIds.Contains($g.id)) { $groupIds.Add($g.id) } }
            }
        }

        $script:LblStatus.Text = "Member of $($groupIds.Count) group(s). Finding applicable policies..."
        [System.Windows.Forms.Application]::DoEvents()

        $policies = Get-AppliedPolicies -GroupIds @($groupIds) -IsDevice $resolveDevice -IsUser $resolveUser -DeviceOS $effectiveOS
        $script:PolicyData = $policies

        if ($policies.Count -eq 0) {
            $script:LblPane.Text = "No policies found for $targetLabel"
            $script:LblStatus.Text = "No policies found for $targetLabel"
            return
        }

        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add('_RowType')           | Out-Null
        $dt.Columns.Add('Policy / Setting')   | Out-Null
        $dt.Columns.Add('Value / Assignment') | Out-Null
        $dt.Columns.Add('_Description')       | Out-Null

        $total = $policies.Count
        $i = 0
        foreach ($p in $policies) {
            $i++
            $script:LblStatus.Text = "Fetching settings $i/$total : $($p.PolicyName)..."
            [System.Windows.Forms.Application]::DoEvents()

            $hdr = $dt.NewRow()
            $hdr['_RowType'] = 'H'
            $hdr['Policy / Setting'] = "$($p.PolicyType)  -  $($p.PolicyName)"
            $hdr['Value / Assignment'] = $p.Assignment
            $hdr['_Description'] = [string]::Empty
            $dt.Rows.Add($hdr)

            try {
                $settingRows = Get-PolicySettings -PolicyId $p.PolicyId -SettingsType $p.SettingsType
                if ($settingRows.Count -eq 0) {
                    $r = $dt.NewRow()
                    $r['_RowType'] = 'S'
                    $r['Policy / Setting'] = '  (no settings retrieved for this policy type)'
                    $r['Value / Assignment'] = [string]::Empty
                    $r['_Description'] = [string]::Empty
                    $dt.Rows.Add($r)
                }
                else {
                    foreach ($sr in $settingRows) {
                        $r = $dt.NewRow()
                        $r['_RowType'] = 'S'
                        $r['Policy / Setting'] = "  $($sr.Setting)"
                        $r['Value / Assignment'] = "$($sr.Value)"
                        $r['_Description'] = if ($sr.Description) { $sr.Description } else { [string]::Empty }
                        $dt.Rows.Add($r)
                    }
                }
            }
            catch {
                $r = $dt.NewRow()
                $r['_RowType'] = 'S'
                $r['Policy / Setting'] = '  ERROR retrieving settings'
                $r['Value / Assignment'] = $_.Exception.Message
                $r['_Description'] = [string]::Empty
                $dt.Rows.Add($r)
            }
        }

        $script:DgvMain.DataSource = $dt
        $script:DgvMain.Columns['_RowType'].Visible = $false
        $script:DgvMain.Columns['_Description'].Visible = $false
        $script:DgvMain.Columns['Policy / Setting'].Width = 500
        $script:DgvMain.Columns['Value / Assignment'].AutoSizeMode = 'Fill'

        $script:BtnExport.Enabled = $true
        $settingCount = $dt.Rows.Count - $policies.Count
        $script:LblPane.Text = "$targetLabel  -  $($policies.Count) policies  |  $settingCount settings"
        $script:LblStatus.Text = "Loaded $($policies.Count) policies and $settingCount settings for $targetLabel"

    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error:`n$($_.Exception.Message)", 'Error', 'OK', 'Error')
        $script:LblStatus.Text = 'Failed.'
        $script:LblPane.Text = 'Load failed.'
    }
    finally {
        $script:Worker = $null
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:BtnSearch.Enabled = $true
        $script:ListResults.Enabled = $true
        $script:CmbDevice.Enabled = $true
    }
}

function Invoke-Export {
    if (-not $script:PolicyData -or $script:PolicyData.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV Files (*.csv)|*.csv'
    $sfd.FileName = "IntuneSettings_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }

    $allRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $total = $script:PolicyData.Count; $i = 0
    foreach ($p in $script:PolicyData) {
        $i++
        $script:LblStatus.Text = "Exporting $i/$total : $($p.PolicyName)..."
        $script:Form.Refresh()
        try {
            $sRows = Get-PolicySettings -PolicyId $p.PolicyId -SettingsType $p.SettingsType
            if ($sRows.Count -gt 0) {
                foreach ($sr in $sRows) {
                    $allRows.Add([PSCustomObject]@{
                            PolicyType = $p.PolicyType
                            PolicyName = $p.PolicyName
                            Assignment = $p.Assignment
                            Setting    = $sr.Setting
                            Value      = $sr.Value
                        })
                }
            }
            else {
                $allRows.Add([PSCustomObject]@{ PolicyType = $p.PolicyType; PolicyName = $p.PolicyName; Assignment = $p.Assignment; Setting = '(no settings)'; Value = ''; Description = '' })
            }
        }
        catch {
            $allRows.Add([PSCustomObject]@{ PolicyType = $p.PolicyType; PolicyName = $p.PolicyName; Assignment = $p.Assignment; Setting = 'ERROR'; Value = $_.Exception.Message; Description = '' })
        }
    }
    $allRows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
    $script:LblStatus.Text = "Exported to: $($sfd.FileName)"
}
#endregion

#region ── Build GUI ──────────────────────────────────────────────────────────
function Build-Form {

    $script:Form = New-Object System.Windows.Forms.Form
    $script:Form.Text = 'Intune Policy Viewer'
    $script:Form.Size = New-Object System.Drawing.Size(1300, 820)
    $script:Form.StartPosition = 'CenterScreen'
    $script:Form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    $script:Form.Font = $script:FontNormal
    $script:Form.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 250)

    #── Top panel ─────────────────────────────────────────────────────────────
    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = 'Top'
    $topPanel.Height = 110
    $topPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = '  Intune Policy Viewer'
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(10, 10)

    $subLabel = New-Object System.Windows.Forms.Label
    $subLabel.Text = '  All settings applied to a device or user, grouped by policy'
    $subLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $subLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 235, 255)
    $subLabel.AutoSize = $true
    $subLabel.Location = New-Object System.Drawing.Point(10, 38)

    $searchPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $searchPanel.Location = New-Object System.Drawing.Point(10, 62)
    $searchPanel.Size = New-Object System.Drawing.Size(1260, 38)
    $searchPanel.FlowDirection = 'LeftToRight'
    $searchPanel.WrapContents = $false

    $lblSearch = New-Object System.Windows.Forms.Label
    $lblSearch.Text = 'Search:'
    $lblSearch.ForeColor = [System.Drawing.Color]::White
    $lblSearch.Font = $script:FontBold
    $lblSearch.AutoSize = $true
    $lblSearch.Margin = New-Object System.Windows.Forms.Padding(0, 7, 6, 0)

    $script:TxtSearch = New-Object System.Windows.Forms.TextBox
    $script:TxtSearch.Width = 300
    $script:TxtSearch.Font = $script:FontNormal
    $script:TxtSearch.Margin = New-Object System.Windows.Forms.Padding(0, 4, 8, 0)

    $script:RbDevice = New-Object System.Windows.Forms.RadioButton
    $script:RbDevice.Text = 'Device'
    $script:RbDevice.ForeColor = [System.Drawing.Color]::White
    $script:RbDevice.Checked = $true
    $script:RbDevice.AutoSize = $true
    $script:RbDevice.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)

    $script:RbUser = New-Object System.Windows.Forms.RadioButton
    $script:RbUser.Text = 'User'
    $script:RbUser.ForeColor = [System.Drawing.Color]::White
    $script:RbUser.AutoSize = $true
    $script:RbUser.Margin = New-Object System.Windows.Forms.Padding(0, 6, 12, 0)

    $script:BtnSearch = New-Object System.Windows.Forms.Button
    $script:BtnSearch.Text = 'Search'
    $script:BtnSearch.Width = 90
    $script:BtnSearch.Height = 28
    $script:BtnSearch.BackColor = [System.Drawing.Color]::White
    $script:BtnSearch.ForeColor = [System.Drawing.Color]::FromArgb(0, 80, 160)
    $script:BtnSearch.FlatStyle = 'Flat'
    $script:BtnSearch.Font = $script:FontBold
    $script:BtnSearch.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 0)

    $script:BtnConnect = New-Object System.Windows.Forms.Button
    $script:BtnConnect.Text = 'Connect to Graph'
    $script:BtnConnect.Width = 140
    $script:BtnConnect.Height = 28
    $script:BtnConnect.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 0)
    $script:BtnConnect.ForeColor = [System.Drawing.Color]::FromArgb(60, 40, 0)
    $script:BtnConnect.FlatStyle = 'Flat'
    $script:BtnConnect.Font = $script:FontBold
    $script:BtnConnect.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)

    $searchPanel.Controls.AddRange(@($lblSearch, $script:TxtSearch, $script:RbDevice, $script:RbUser, $script:BtnSearch, $script:BtnConnect))
    $topPanel.Controls.AddRange(@($titleLabel, $subLabel, $searchPanel))

    #── Outer split: Left (results list) | Right (all-settings pane) ──────────
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.BackColor = [System.Drawing.Color]::FromArgb(200, 200, 205)

    # Left pane — search results list
    $split.Panel1.BackColor = [System.Drawing.Color]::White

    $lblResults = New-Object System.Windows.Forms.Label
    $lblResults.Text = 'Search Results'
    $lblResults.Dock = 'Top'
    $lblResults.Height = 26
    $lblResults.TextAlign = 'MiddleLeft'
    $lblResults.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $lblResults.Font = $script:FontBold
    $lblResults.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 240)
    $script:ListResults = New-Object System.Windows.Forms.ListBox
    $script:ListResults.Dock = 'Fill'
    $script:ListResults.Font = $script:FontNormal
    $script:ListResults.BorderStyle = 'None'
    $script:ListResults.IntegralHeight = $false
    $split.Panel1.Controls.Add($script:ListResults)
    $split.Panel1.Controls.Add($lblResults)

    # Right pane — header label + main grid
    $split.Panel2.BackColor = [System.Drawing.Color]::White

    $script:LblPane = New-Object System.Windows.Forms.Label
    $script:LblPane.Text = 'Select a device or user from the left to load all applied settings'
    $script:LblPane.Dock = 'Top'
    $script:LblPane.Height = 26
    $script:LblPane.TextAlign = 'MiddleLeft'
    $script:LblPane.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $script:LblPane.Font = $script:FontBold
    $script:LblPane.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 240)
    $script:DgvMain = New-Object System.Windows.Forms.DataGridView
    $script:DgvMain.Dock = 'Fill'
    $script:DgvMain.ReadOnly = $true
    $script:DgvMain.AllowUserToAddRows = $false
    $script:DgvMain.AutoSizeColumnsMode = 'Fill'
    $script:DgvMain.ColumnHeadersHeightSizeMode = 'AutoSize'
    $script:DgvMain.BackgroundColor = [System.Drawing.Color]::White
    $script:DgvMain.BorderStyle = 'None'
    $script:DgvMain.RowHeadersVisible = $false
    $script:DgvMain.SelectionMode = 'FullRowSelect'
    $script:DgvMain.MultiSelect = $false
    $script:DgvMain.Font = $script:FontNormal
    $script:DgvMain.GridColor = [System.Drawing.Color]::FromArgb(220, 220, 225)
    $script:DgvMain.CellBorderStyle = 'SingleHorizontal'

    # Row painter: header rows get dark blue + bold, excluded get red tint
    $script:DgvMain.Add_CellFormatting({
            $rowIdx = $_.RowIndex
            if ($rowIdx -lt 0) { return }
            $rowType = $script:DgvMain.Rows[$rowIdx].Cells['_RowType'].Value
            if ($rowType -eq 'H') {
                $_.CellStyle.BackColor = $script:ColPolicyHeader
                $_.CellStyle.ForeColor = $script:ColPolicyText
                $_.CellStyle.Font = $script:FontBold
            }
            elseif ($script:DgvMain.Rows[$rowIdx].Cells['Value / Assignment'].Value -like '*EXCLUDED*') {
                $_.CellStyle.BackColor = $script:ColExcluded
                $_.CellStyle.ForeColor = $script:ColExcludedText
            }
            elseif ($rowIdx % 2 -eq 0) {
                $_.CellStyle.BackColor = $script:ColSettingAlt
            }
        })

    # ToolTip for setting descriptions
    $script:ToolTip = New-Object System.Windows.Forms.ToolTip
    $script:ToolTip.AutoPopDelay = 12000   # stay visible 12s
    $script:ToolTip.InitialDelay = 400
    $script:ToolTip.ReshowDelay = 200
    $script:ToolTip.ShowAlways = $true

    # Tooltip: show description from hidden _Description column
    $script:DgvMain.ShowCellToolTips = $false  # we handle manually for more control
    $script:DgvMain.Add_CellMouseEnter({
            $rowIdx = $_.RowIndex
            $colIdx = $_.ColumnIndex
            if ($rowIdx -lt 0 -or $colIdx -lt 0) { return }
            $row = $script:DgvMain.Rows[$rowIdx]
            if ($row.Cells['_RowType'].Value -eq 'H') { return }  # no tooltip on headers
            $desc = "$($row.Cells['_Description'].Value)"
            $setting = "$($row.Cells['Policy / Setting'].Value)".Trim()
            if ([string]::IsNullOrEmpty($desc)) {
                $tipText = "$setting`n`n(No description available)`n`nDouble-click to search MS Docs"
            }
            else {
                $tipText = "$setting`n`n$desc`n`nDouble-click to search MS Docs"
            }
            $script:ToolTip.SetToolTip($script:DgvMain, $tipText)
        })
    $script:DgvMain.Add_CellMouseLeave({
            $script:ToolTip.SetToolTip($script:DgvMain, [string]::Empty)
        })

    # Double-click: open MS Learn search for this setting
    $script:DgvMain.Add_CellDoubleClick({
            $rowIdx = $_.RowIndex
            if ($rowIdx -lt 0) { return }
            $row = $script:DgvMain.Rows[$rowIdx]
            if ($row.Cells['_RowType'].Value -eq 'H') { return }
            $setting = "$($row.Cells['Policy / Setting'].Value)".Trim()
            if ([string]::IsNullOrEmpty($setting)) { return }
            $encoded = [Uri]::EscapeDataString($setting)
            $url = "https://learn.microsoft.com/en-us/search/?terms=$encoded&category=Documentation&scope=Intune"
            Start-Process $url
        })

    # Device filter panel (only visible in user mode when devices exist)
    $script:PnlFilter = New-Object System.Windows.Forms.Panel
    $script:PnlFilter.Dock = 'Top'
    $script:PnlFilter.Height = 36
    $script:PnlFilter.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 255)
    $script:PnlFilter.Visible = $false
    $script:PnlFilter.Padding = New-Object System.Windows.Forms.Padding(6, 4, 6, 4)

    $lblDevFilter = New-Object System.Windows.Forms.Label
    $lblDevFilter.Text = 'Filter by device:'
    $lblDevFilter.AutoSize = $true
    $lblDevFilter.Font = $script:FontBold
    $lblDevFilter.Location = New-Object System.Drawing.Point(8, 9)

    $script:CmbDevice = New-Object System.Windows.Forms.ComboBox
    $script:CmbDevice.DropDownStyle = 'DropDownList'
    $script:CmbDevice.Font = $script:FontNormal
    $script:CmbDevice.Width = 420
    $script:CmbDevice.Location = New-Object System.Drawing.Point(118, 6)
    $script:CmbDevice.Items.Add('User policies (no device filter)') | Out-Null
    $script:CmbDevice.SelectedIndex = 0

    $script:PnlFilter.Controls.Add($lblDevFilter)
    $script:PnlFilter.Controls.Add($script:CmbDevice)

    $split.Panel2.Controls.Add($script:DgvMain)
    $split.Panel2.Controls.Add($script:PnlFilter)
    $split.Panel2.Controls.Add($script:LblPane)

    #── Status bar ────────────────────────────────────────────────────────────
    $statusBar = New-Object System.Windows.Forms.Panel
    $statusBar.Dock = 'Bottom'
    $statusBar.Height = 30
    $statusBar.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 235)

    $script:LblStatus = New-Object System.Windows.Forms.Label
    $script:LblStatus.Text = 'Connect to Microsoft Graph to begin.  |  Hover a setting for description  ·  Double-click to search MS Docs'
    $script:LblStatus.Dock = 'Fill'
    $script:LblStatus.TextAlign = 'MiddleLeft'
    $script:LblStatus.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $script:LblStatus.Font = New-Object System.Drawing.Font('Segoe UI', 8)

    $script:BtnExport = New-Object System.Windows.Forms.Button
    $script:BtnExport.Text = 'Export CSV'
    $script:BtnExport.Dock = 'Right'
    $script:BtnExport.Width = 100
    $script:BtnExport.FlatStyle = 'Flat'
    $script:BtnExport.Font = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
    $script:BtnExport.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $script:BtnExport.ForeColor = [System.Drawing.Color]::White
    $script:BtnExport.Enabled = $false

    $statusBar.Controls.Add($script:BtnExport)
    $statusBar.Controls.Add($script:LblStatus)

    $script:Form.Controls.Add($split)
    $script:Form.Controls.Add($topPanel)
    $script:Form.Controls.Add($statusBar)

    #── Wire events ───────────────────────────────────────────────────────────
    $script:BtnConnect.Add_Click({ Invoke-Connect })
    $script:BtnSearch.Add_Click({ Invoke-Search })
    $script:BtnExport.Add_Click({ Invoke-Export })
    $script:TxtSearch.Add_KeyDown({ if ($_.KeyCode -eq 'Return') { $_.SuppressKeyPress = $true; Invoke-Search } })
    $script:ListResults.Add_SelectedIndexChanged({ Invoke-LoadAll })
    $script:CmbDevice.Add_SelectedIndexChanged({ Invoke-LoadAll -FromDeviceFilter })
}
#endregion

#region ── Entry Point ────────────────────────────────────────────────────────
Build-Form
[System.Windows.Forms.Application]::Run($script:Form)
#endregion