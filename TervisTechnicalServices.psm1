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

function New-TervisMESUser {
    param(
        [Parameter(ValueFromPipeline,Mandatory)]$FirstName,
        [Parameter(ValueFromPipeline,Mandatory)]$LastName,
        [Parameter(ValueFromPipeline,Mandatory)]$Username,
        [Parameter(ValueFromPipeline)]$MiddleInitial
    )
    $OUPath = "OU=Users,OU=Production Floor,OU=Operations,OU=Departments,DC=tervis,DC=prv"
    $UPN = "$Username@tervis.prv"
    $Department = "Production"

    if($MiddleInitial) {
    
        New-ADUser -Name "$FirstName $MiddleInitial $LastName" -GivenName $FirstName -Surname $LastName -Initials $MiddleInitial -DisplayName "$FirstName $MiddleInitial $LastName" -UserPrincipalName $UPN -Path $OUPath -SamAccountName $Username -Department $Department
        
        }

        else {

        New-ADUser -Name "$FirstName $LastName" -GivenName $FirstName -Surname $LastName -DisplayName "$FirstName $LastName" -UserPrincipalName $UPN -Path $OUPath -SamAccountName $Username -Department $Department

        }
}

function Invoke-TervisVOIPTerminateUser {
    param (
        [Parameter(Mandatory)]$SamAccountName
    )
    Invoke-TervisCUCMTerminateUser -UserName $SamAccountName
    Invoke-TervisCUCTerminateVM -Alias $SamAccountName
    Set-ADUser $SamAccountName -Clear TelephoneNumber
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
        [Parameter(Mandatory, ParameterSetName="ManagerReceivesData")][Switch]$ManagerReceivesData,
        [Parameter(Mandatory, ParameterSetName="AnotherUserReceivesData")]$IdentityOfUserToReceiveData,
        [Parameter(Mandatory, ParameterSetName="NoUserReceivesData")][Switch]$NoUserReceivesData,        
        [Parameter(ParameterSetName="ManagerReceivesData")][Parameter(ParameterSetName="AnotherUserReceivesData")][Switch]$DeleteFilesWithoutMovingThem,
        [Switch]$UserWasITEmployee
    )
    $ADUser = Get-ADUser -Identity $Identity -Properties Manager, HomeDirectory

    if ($NoUserReceivesData) {
        $DeleteFilesWithoutMovingThem = $true
        $IdentityOfUserToReceiveData = $null
    }

    if ($ManagerReceivesData) {
        if( -not $ADUser.Manager) { 
            Throw "ManagerReceivesData was specified but the user doesn't have a manager in Active Directory" 
        }
        $IdentityOfUserToReceiveData = (Get-ADUser ($ADUser.Manager)).SamAccountName
    }        

    Invoke-TervisVOIPTerminateUser -SamAccountName $Identity -Verbose

    if ($DeleteFilesWithoutMovingThem -and $ADUser.HomeDirectory) {
        Remove-TervisADUserHomeDirectory -Identity $Identity
    } elseif ($ADUser.HomeDirectory) {
        Invoke-TervisADUserShareHomeDirectoryPathAndClearHomeDirectoryProperty -Identity $Identity -IdentityOfUserToAccessHomeDirectoryFiles $IdentityOfUserToReceiveData
    }
    
    Remove-TervisMSOLUser -Identity $Identity -IdentityOfUserToReceiveAccessToRemovedUsersMailbox $IdentityOfUserToReceiveData -AzureADConnectComputerName dirsync
    Remove-TervisADUser -Identity $Identity

    if ($UserWasITEmployee) {
        Send-ITTerminationEmails -Identity $Identity
    }

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

function Send-ITTerminationEmails {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]$Identity
    )
    
    $Emails = (
        ($EmailAddressToCDW = "andydai@cdw.com"),
        ($EmailAddressToSHI = "anthony_geremia@shi.com; todd_rigden@shi.com"),
        ($EmailAddressToDell = "russel_dunn@dell.com"),
        ($EmailAddressToATT = "joe.rivkin@att.net")
    )

    $NameOfTerminatedEmployee = (Get-ADUser -Identity $Identity).Name
    $To = 
    $Bcc = $Emails
    $From = "helpdeskteam@tervis.com"
    $Subject = "$NameOfTerminatedEmployee is no longer working for Tervis."
    $Body = @"
Hello,

$NameOfTerminatedEmployee is no longer working for Tervis.  Please remove them from your system.

Thank you,

Tervis IT

"@

    Send-TervisMailMessage -To $To -Bcc $Bcc -From $From -Subject $Subject -Body $Body
}

function Remove-TervisProductionUser {
    param(
        [Parameter(Mandatory)]$Identity
    )
    $MSOnlineMailboxExists = Test-TervisUserHasMSOnlineMailbox -Identity $Identity
    $OnPremMailboxExists = Test-TervisUserHasOnPremMailbox -Identity $Identity

    if($MSOnlineMailboxExists) {
        Write-Output "The user account $Identity has an Office 365 mailbox.  Please run the function 'Remove-TervisUser' for this user."

    } elseif($OnPremMailboxExists) {
        Write-Output "The user account $Identity has an On Premises Exchange 2016 mailbox.  Please contact their manager to see if they need access to the user's email."
        } else {
        Write-Output "User has no mailbox, removing user account."
        Remove-ADUser -Identity $Identity -Confirm
        }
}

function Get-EBSResponsibility {
    param (
        $PathToMatrix = "\\tervis.prv\Applications\PowerShell\EBSResponsibilityMatrix\EBS Responsibility Owner_Approver Matrix_09JUN2017.csv",
        [ValidateSet(
            "Development Manager","Tervis Advanced Supply Chain Planner","Tervis Approval Setup","Tervis Batch Requests","Tervis BI Fin SCOM Analyst","Tervis BI FIN SCOM End User","Tervis BI FIN SCOM Super User","Tervis BI SCOM Analyst","Tervis BI SCOM End User","Tervis BI SCOM Super User","Tervis Bills of Material","Tervis BOM Inquiry","Tervis Buyer (Stores)","Tervis Buyer/Planner","Tervis Cash Management Superuser","Tervis Cash Management User","Tervis Concurrent Request Support","Tervis Contract MFG","Tervis Cost Management - SLA","Tervis Cost Management User","Tervis CRM Resource Manager","Tervis Desktop Integrator","Tervis Discoverer Reports","Tervis Expense Report Signing Limits","Tervis Finance Order Management","Tervis Fixed Assets Manager","Tervis Flow Manufacturing","Tervis General Ledger Budget","Tervis Help Desk","Tervis Internet Expenses","Tervis Internet Expenses Auditor","Tervis Internet Expenses Setup and Administration","Tervis Inventory & Manufacturing","Tervis Inventory Inquiry","Tervis Inventory Steward","Tervis Inventory Super User","Tervis Inventory/Receiving","Tervis Inventory/Receiving - Lakeland","Tervis iProcurement","Tervis iProcurement (Internal Requisitions)","Tervis iProcurement (Tervis Stores)","Tervis Location Setup","Tervis Manufacturing Engineer","Tervis Materials & Mfg","Tervis OM CC User","Tervis OM Custom","Tervis OM Inquiry","Tervis OM IT","Tervis OM Item Orderability","Tervis OM Management Team","Tervis OM Pricing","Tervis OM Sales Rep","Tervis OM Super User","Tervis OM User","Tervis Payables Inquiry","Tervis Payables Invoice Inquiry","Tervis Payables Manager","Tervis Payables User","Tervis Payments Setup Administrator","Tervis PIM Data Steward","Tervis PIM Data Viewer","Tervis PIM Data Viewer Plus Import","Tervis Production Control","Tervis Purchasing Accounting","Tervis Purchasing Inquiry","Tervis Purchasing Super User","Tervis Receivables Manager","Tervis Receivables User","Tervis Replenishment Buyer","Tervis RXI","Tervis Sales Support","Tervis Supply Chain Planner","Tervis Tax Managers","Tervis Trade Management Administrator","Tervis Trade Management User","Tervis Trading Community Manager","Tervis US HRMS Manager","Tervis WEB Data Integration","Tervis Work in Process"
        )]$ResponsibilityName
    )
    $Matrix = Import-Csv -Path $PathToMatrix
    $Matrix | where ResponsibilityName -EQ $ResponsibilityName
}