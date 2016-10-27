#Requires -Modules TervisCUCM, TervisCUPI, CUCMPowerShell, TervisActiveDirectory, TervisMSOnline

function Install-TervisTechnicalServices {
    if(-not (Get-PasswordStateAPIKey -ErrorAction SilentlyContinue)){
        Install-PasswordStatePowerShell
    }
    Install-TervisMSOnline
    Install-TervisCUCM
    Install-TervisCUPI
    Invoke-EnvironmentVariablesRefresh
}

function New-TervisEmployee {
    param(
        $GivenName,
        $SurName,
        $EmployeeID,
        $EmployeeIDOfExistingEmployeeToModelPermissionsAfter,
        [Switch]$Mac,
        [Switch]$Laptop,
        [Switch]$DualMonitors
    )
}

function Invoke-TervisVOIPTerminateUser {
    param (
        [Parameter(Mandatory)]$SamAccountName
    )

    Invoke-TervisCUCMTerminateUser -UserName $SamAccountName
    Invoke-TervisCUCTerminateVM -Alias $SamAccountName 
    Set-ADUser $SamAccountName -OfficePhone $null
}

Function New-TervisVOIPUser {
    param (
        [Parameter(Mandatory)][ValidateSet("CallCenterAgent")] [String]$UserType,
        [Parameter(Mandatory)][String]$UserID
    )

    if ($UserType -eq "CallCenterAgent") {
        $Pattern = Find-CUCMLine -Pattern 7% -Description "" | select -First 1
        Set-ADUser $UserID -OfficePhone $Pattern
        Sync-CUCMtoLDAP -LDAPDirectory TERV_AD

        do {
            sleep -Seconds 3
        } until (Get-CUCMUser -UserID $UserID -ErrorAction SilentlyContinue)

        $ADUser = Get-ADUser $UserID
        $DisplayName = $ADUser.name
        $DeviceName = "CSF"
        
        $Parameters = @{
            Pattern = $Pattern
            routePartition = "UCCX_PT"
            CSS = "UCCX_CSS"
            Description = $DisplayName
            AlertingName = $DisplayName
            AsciiAlertingName = $DisplayName
            userHoldMohAudioSourceId = "0"
            networkHoldMohAudioSourceId = "0"
            voiceMailProfileName = "Voicemail"
            CallForwardAllForwardToVoiceMail = "False"
            CallForwardAllcallingSearchSpaceName = "UCCX_CSS"
            CallForwardAllsecondarycallingSearchSpaceName = "UCCX_CSS"
            CallForwardBusyForwardToVoiceMail= "True"
            CallForwardBusycallingSearchSpaceName = "UCCX_CSS"
            CallForwardBusyIntForwardToVoiceMail = "True"
            CallForwardBusyIntcallingSearchSpaceName = "UCCX_CSS"
            CallForwardNoAnswerForwardToVoiceMail = "True"
            CallForwardNoAnswercallingSearchSpaceName = "UCCX_CSS"
            CallForwardNoAnswerIntForwardToVoiceMail = "True"
            CallForwardNoAnswerIntcallingSearchSpaceName = "UCCX_CSS"
            CallForwardNoCoverageForwardToVoiceMail = "True"
            CallForwardNoCoveragecallingSearchSpaceName = "UCCX_CSS"
            CallForwardNoCoverageIntForwardToVoiceMail = "True"
            CallForwardNoCoverageIntcallingSearchSpaceName = "UCCX_CSS"
            CallForwardOnFailureForwardToVoiceMail = "True"
            CallForwardOnFailurecallingSearchSpaceName = "UCCX_CSS"
            CallForwardNotRegisteredForwardToVoiceMail = "True"
            CallForwardNotRegisteredcallingSearchSpaceName = "UCCX_CSS"
            CallForwardNotRegisteredIntForwardToVoiceMail = "True"
            CallForwardNotRegisteredIntcallingSearchSpaceName = "UCCX_CSS"
            index = "1"
            Display = $DisplayName
            
        }

        $Dirnuuid = Set-CUCMAgentLine @Parameters

        $Parameters = @{
            UserID = $UserID
            DeviceName = "$DeviceName" + $UserID
            Description = $DisplayName
            Product = "Cisco Unified Client Services Framework"
            Class = "Phone"
            Protocol = "SIP"
            ProtocolSide = "User"
            CallingSearchSpaceName = "Gateway_outbound_CSS"
            DevicePoolName = "TPA_DP"
            SecurityProfileName = "Cisco Unified Client Services Framework - Standard SIP Non-Secure"
            SipProfileName = "Standard SIP Profile"
            MediaResourceListName = "TPA_MRL"
            Locationname = "Hub_None"
            Dirnuuid = $Dirnuuid
            Label = $DisplayName
            AsciiLabel = $DisplayName
            Display = $DisplayName
            DisplayAscii = $DisplayName
            E164Mask = "941441XXXX"
            PhoneTemplateName = "Standard Client Services Framework"
        
        }
        
        Add-CUCMPhone @Parameters
        
        $Parameters = @{
            UserID = $UserID
            Pattern = $Pattern
            imAndPresenceEnable = "True"
            serviceProfile = "UCServiceProfile_Migration_1"
            DeviceName = "$DeviceName" + $UserID
            routePartitionName = "UCCX_PT"
            userGroupName = "CCM END USER SETTINGS"
            userRolesName = "CCM END USER SETTINGS"

        }
       
       Set-CUCMUser @Parameters

       $Parameters = @{
           Pattern = $Pattern
           UserID = $UserID
           RoutePartition = "UCCX_PT"
           CSS = "UCCX_CSS"

       }

       Set-CUCMIPCCExtension @Parameters

       

       $CUCMAppuser = Get-CUCMAppuser -UserID AXL_uccx_RmCm
       $DeviceNames = @($CUCMAppuser.associatedDevices.device)
       $DeviceNames += "$DeviceName" + $UserID
       Set-CUCMAppuser -UserID AXL_uccx_RmCm -DeviceNames $DeviceNames
    
    }

}

function Remove-TervisUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Identity,
        $IdentityOfUserToRecieveAccessToRemovedUsersMailbox,
        [Parameter(Mandatory, ParameterSetName="ManagerReceivesFiles")][Switch]$ManagerReceivesFiles,
        [Parameter(Mandatory, ParameterSetName="AnotherUserReceivesFiles")]$IdentityOfUserToReceiveHomeDirectoryFiles,        
        [Parameter(Mandatory, ParameterSetName="DeleteUsersFiles")][Switch]$DeleteFilesWithoutMovingThem
    )
    
    Invoke-TervisVOIPTerminateUser -SamAccountName $Identity -Verbose

    Write-Verbose "Checking if Supervisor's computer is a Mac..."
    $ADUser = Get-ADUser -Identity $Identity -Properties Manager
    $SupervisorComputerObject = Find-TervisADUsersComputer -SAMAccountName $IdentityOfUserToReceiveAccessToUsersHomeDirectoryAndEmail
    $SupervisorComputerObjectName = $SupervisorComputerObject.Name

    if($SupervisorComputerObjectName -like "*-mac") {
        Write-Verbose "Sending instructions to supervisor for Outlook for Mac..."
        Send-SupervisorOfTerminatedUserSharedEmailInstructions -UserNameOfTerminatedUser $Identity -UserNameOfSupervisor $IdentityOfUserToReceiveAccessToUsersHomeDirectoryAndEmail
        Read-Host "Please move the terminated user's files to the recipient's Mac manually using Teamviewer. Press `"Enter`" when this has been completed."
    } else {
        Write-Verbose "Supervisor's computer is not a Mac, moving along..."
        Remove-TervisADUserHomeDirectory @PSBoundParameters
    }
    
    Remove-TervisMSOLUser -Identity $Identity -IdentityOfUserToRecieveAccessToRemovedUsersMailbox $IdentityOfUserToRecieveAccessToRemovedUsersMailbox -AzureADConnectComputerName dirsync
}

function Invoke-EnvironmentVariablesRefresh {   
    $locations = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
                 'HKCU:\Environment'

    $locations | ForEach-Object {   
        $k = Get-Item $_
        $k.GetValueNames() | ForEach-Object {
            $name  = $_
            $value = $k.GetValue($_)
            Set-Item -Path Env:\$name -Value $value
        }
    }
}