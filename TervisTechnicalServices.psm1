#Requires -Modules TervisCUCM, TervisCUPI, CUCMPowerShell, TervisActiveDirectory, TervisMSOnline, TervisApplication

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

function Send-EBSResponsibilityApprovalRequestEmail {
    param(
        [parameter(mandatory)]$EBSUsernameOfEmployeeNeedingEBSResponsibility,
        $PathToMatrix = "\\$(Get-DomainName -ComputerName $env:COMPUTERNAME)\applications\PowerShell\EBSResponsibilityMatrix\EBSResponsibilityOwnerApproverMatrix.csv"
    )
    
    $Matrix = Import-Csv -Path $PathToMatrix
    $MatrixGridResponsibilities = $Matrix | Out-GridView -PassThru

    foreach ($EBSResponsibility in $MatrixGridResponsibilities){
        #$EBSResponsibility = Get-EBSResponsibility -ResponsibilityName $Responsibility -PathToMatrix $PathToMatrix
        $EBSResponsibilityApprover = $EBSResponsibility.Approver
        $EBSResponsibilityApproverEmail = $EBSResponsibility.ApproverEmail
        $EBSResponsibilityName = $EBSResponsibility.ResponsibilityName

        if ($EBSResponsibilityApprover -ne "none") {
            $From = "helpdeskteam@tervis.com"
            $To = $EBSResponsibilityApproverEmail
            $Subject = "Approval of EBS Responsibility $EBSResponsibilityName for $EBSUsernameOfEmployeeNeedingEBSResponsibility"
            $Body = 
@"
$EBSResponsibilityApprover,

Do you approve of EBS user $EBSUsernameOfEmployeeNeedingEBSResponsibility having access to the following EBS responsibility?
$EBSResponsibilityName

Thanks,

Help Desk
"@
            Send-TervisMailMessage -To $To -From $From -Subject $Subject -Body $Body
        }
    }
}

function Get-EBSResponsibilityApprovalMatrix {
    param(
        $PathToMatrix = "\\$(Get-DomainName -ComputerName $env:COMPUTERNAME)\applications\PowerShell\EBSResponsibilityMatrix\EBSResponsibilityOwnerApproverMatrix.csv"
    )
    $Matrix = Import-Csv -Path $PathToMatrix
    $MatrixGridResponsibilities = $Matrix | Out-GridView -PassThru
}

function New-TervisProductionUser{
    param(
        [parameter(mandatory)]$FirstName,
        [parameter(mandatory)]$LastName,
        $MiddleInitial,
        [parameter(mandatory)]$AzureADConnectComputerName,
        [switch]$MultipleUsers = $false
    )

    $SourceUserName = "sourceusertemplate"

    [string]$FirstInitialLastName = $FirstName[0] + $LastName
    [string]$FirstNameLastInitial = $FirstName + $LastName[0]

    If (!(Get-ADUser -filter {sAMAccountName -eq $FirstInitialLastName})) {
        [string]$UserName = $FirstInitialLastName.substring(0).tolower()
        Write-Host "UserName is $UserName" -ForegroundColor Green
    } elseif (!(Get-ADUser -filter {sAMAccountName -eq $FirstNameLastInitial})) {
        [string]$UserName = $FirstNameLastInitial
        Write-Host 'First initial + last name is in use.' -ForegroundColor Red
        Write-Host "UserName is $UserName" -ForegroundColor Green
    } else {
        Write-Host 'First initial + last name is in use.' -ForegroundColor Red
        Write-Host 'First name + last initial is in use.' -ForegroundColor Red
        Write-Host 'You will need to manually define $UserName' -ForegroundColor Red
        $UserName = $null
    }

    If (!($UserName -eq $null)) {

        [string]$AdDomainNetBiosName = (Get-ADDomain | Select -ExpandProperty NetBIOSName).substring(0).tolower()
        [string]$Company = $AdDomainNetBiosName.substring(0,1).toupper()+$AdDomainNetBiosName.substring(1).tolower()
        [string]$DisplayName = $FirstName + ' ' + $LastName
        [string]$UserPrincipalName = $username + '@' + $AdDomainNetBiosName + '.com'
        [string]$LogonName = $AdDomainNetBiosName + '\' + $username
        [string]$Path = Get-ADUser $SourceUserName -Properties distinguishedname,cn | select @{n='ParentContainer';e={$_.distinguishedname -replace '^.+?,(CN|OU.+)','$1'}} | Select -ExpandProperty ParentContainer

        $PW= Get-TempPassword -MinPasswordLength 8 -MaxPasswordLength 12 -FirstChar abcdefghjkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ23456789
        $SecurePW = ConvertTo-SecureString $PW -asplaintext -force

        $Office365Credential = Get-ExchangeOnlineCredential
        $OnPremiseCredential = Import-Clixml $env:USERPROFILE\OnPremiseExchangeCredential.txt
         
        if ($MiddleInitial) {
            New-ADUser `
                -SamAccountName $Username `
                -Name $DisplayName `
                -GivenName $FirstName `
                -Surname $LastName `
                -Initials $MiddleInitial `
                -UserPrincipalName $UserPrincipalName `
                -AccountPassword $SecurePW `
                -ChangePasswordAtLogon $false `
                -Path $Path `
                -Company $Company `
                -Department "Production" `
                -Office "Production" `
                -Description "Production" `
                -Title "Production" `
                -Enabled $false
        } else {
            New-ADUser `
                -SamAccountName $Username `
                -Name $DisplayName `
                -GivenName $FirstName `
                -Surname $LastName `
                -UserPrincipalName $UserPrincipalName `
                -AccountPassword $SecurePW `
                -ChangePasswordAtLogon $false `
                -Path $Path `
                -Company $Company `
                -Department "Production" `
                -Office "Production" `
                -Description "Production" `
                -Title "Production" `
                -Enabled $false `
        }

        $NewUserCredential = Import-PasswordStateApiKey -Name 'NewUser'
        New-PasswordStatePassword -ApiKey $NewUserCredential -PasswordListId 78 -Title $DisplayName -Username $LogonName -Password $SecurePW

        $Groups = Get-ADUser $SourceUserName -Properties MemberOf | Select -ExpandProperty MemberOf

        Foreach ($Group in $Groups) {
            Add-ADGroupMember -Identity $group -Members $UserName
        }
        
        Set-ADUser -CannotChangePassword $true -PasswordNeverExpires $true -Identity $UserName

        If (!($MultipleUsers)){
        Write-Verbose "Forcing a sync between domain controllers"
        $DC = Get-ADDomainController | select -ExpandProperty HostName
        Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
        Start-Sleep 30
        }
    }
}
function New-TervisProductionUsers{
    param(
        $PathToCSV = "\\$(Get-DomainName -ComputerName $env:COMPUTERNAME)\applications\PowerShell\New-TervisProductionUsers\TervisProductionUsers.csv"
    )
    $TervisProductionUsers = Import-Csv -Path $PathToCSV

    foreach ($TervisProductionUser in $TervisProductionUsers){
        $FirstName = $TervisProductionUser.FirstName
        $LastName = $TervisProductionUser.LastName

        New-TervisProductionUser -FirstName $FirstName -LastName $LastName -AzureADConnectComputerName DirSync -MultipleUsers -Verbose
    }
        Write-Verbose "Forcing a sync between domain controllers"
        $DC = Get-ADDomainController | select -ExpandProperty HostName
        Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
        Start-Sleep 30
}

function New-TervisContractor {
    [CmdletBinding()]
    Param(
        [parameter(mandatory)]$FirstName,
        [parameter(mandatory)]$LastName,
        [parameter(Mandatory)]$EmailAddress,
        [parameter(mandatory)]$ManagerUserName,
        [parameter(mandatory)]$Title,
        [parameter(Mandatory)]$Description
    )
    DynamicParam {
            $ParameterName = 'Company'
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 4
            $AttributeCollection.Add($ParameterAttribute)
            $arrSet = Get-TervisContractorDefinition -All | select Name -ExpandProperty Name
            $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
            $AttributeCollection.Add($ValidateSetAttribute)
            $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
            return $RuntimeParameterDictionary
    }
    begin {
        $Company = $PsBoundParameters[$ParameterName]
    }
    
    process {
        [string]$FirstInitialLastName = $FirstName[0] + $LastName
        [string]$FirstNameLastInitial = $FirstName + $LastName[0]
    
        If (!(Get-ADUser -filter {sAMAccountName -eq $FirstInitialLastName})) {
            [string]$UserName = $FirstInitialLastName.substring(0).tolower()
            Write-Host "UserName is $UserName" -ForegroundColor Green
        } elseif (!(Get-ADUser -filter {sAMAccountName -eq $FirstNameLastInitial})) {
            [string]$UserName = $FirstNameLastInitial
            Write-Host 'First initial + last name is in use.' -ForegroundColor Red
            Write-Host "UserName is $UserName" -ForegroundColor Green
        } else {
            Write-Host 'First initial + last name is in use.' -ForegroundColor Red
            Write-Host 'First name + last initial is in use.' -ForegroundColor Red
            Write-Host 'You will need to manually define $UserName' -ForegroundColor Red
            $UserName = $null
        }
    
        If (!($UserName -eq $null)) {
    
            [string]$AdDomainNetBiosName = (Get-ADDomain | Select -ExpandProperty NetBIOSName).substring(0).tolower()
            [string]$DisplayName = $FirstName + ' ' + $LastName
            [string]$UserPrincipalName = $username + '@' + $AdDomainNetBiosName + '.com'
            [string]$LogonName = $AdDomainNetBiosName + '\' + $username
            [string]$Path = Get-ADUser $ManagerUserName | select distinguishedname -ExpandProperty distinguishedname | Get-ADObjectParentContainer
            $ManagerDN = Get-ADUser $ManagerUserName | Select -ExpandProperty DistinguishedName
            if ((Get-ADGroup -Filter {SamAccountName -eq $Company}) -eq $null ){
                New-ADGroup -Name $Company -GroupScope Universal -GroupCategory Security
            }
            $CompanySecurityGroup = Get-ADGroup -Identity $Company
            $PW= Get-TempPassword -MinPasswordLength 8 -MaxPasswordLength 12 -FirstChar abcdefghjkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ23456789
            $SecurePW = ConvertTo-SecureString $PW -asplaintext -force
    
            
            if ($MiddleInitial) {
               New-ADUser `
                    -SamAccountName $Username `
                    -Name $DisplayName `
                    -GivenName $FirstName `
                    -Surname $LastName `
                    -Initials $MiddleInitial `
                    -UserPrincipalName $UserPrincipalName `
                    -AccountPassword $SecurePW `
                    -ChangePasswordAtLogon $true `
                    -Path $Path `
                    -Description $Description `
                    -Company $Company `
                    -Department $Department `
                    -Office $Department `
                    -Description $Description `
                    -Title $Title `
                    -Manager $ManagerDN `
                    -Enabled $true
            } else {
                New-ADUser `
                    -SamAccountName $Username `
                    -Name $DisplayName `
                    -GivenName $FirstName `
                    -Surname $LastName `
                    -UserPrincipalName $UserPrincipalName `
                    -AccountPassword $SecurePW `
                    -ChangePasswordAtLogon $true `
                    -Path $Path `
                    -Company $Company `
                    -Department $Department `
                    -Office $Department `
                    -Description $Description `
                    -Title $Title `
                    -Manager $ManagerDN `
                    -Enabled $true
            }
            Add-ADGroupMember $CompanySecurityGroup -Members $UserName
            New-MailContact -FirstName $FirstName -LastName $LastName -Name $DisplayName -ExternalEmailAddress $EmailAddress 
            
            $NewUserCredential = Import-PasswordStateApiKey -Name 'NewUser'
            New-PasswordStatePassword -ApiKey $NewUserCredential -PasswordListId 78 -Title $DisplayName -Username $LogonName -Password $SecurePW
    
            Write-Verbose "Forcing a sync between domain controllers"
            $DC = Get-ADDomainController | Select -ExpandProperty HostName
            Invoke-Command -ComputerName $DC -ScriptBlock {repadmin /syncall}
            Send-TervisContractorWelcomeLetter -Name $DisplayName -EmailAddress $EmailAddress
        }
    }
}

function Get-TervisContractorDefinition {
    Param(
        [parameter(Mandatory, ParameterSetName="Specify Company Name")]$Company,
        [parameter(Mandatory, ParameterSetName="Return All")][switch]$All
    )
    if ($All) { 
        $TervisContractorDefinitions 
    }
    else {
        $TervisContractorDefinitions | where name -eq $Company
    }
}

$TervisContractorDefinitions = [PSCustomObject][Ordered] @{
    Name = "Trevera"
    RoleSecurityGroup = "OracleManagedServices"
},
[PSCustomObject][Ordered] @{
    Name = "Oracle Managed Services"
    RoleSecurityGroup = "Oracle Managed Services"
}

function Send-TervisContractorWelcomeLetter {
    param (
        [parameter(Mandatory)]$Name,
        [parameter(Mandatory)]$EmailAddress
    )

    $TervisContractorWelcomeLetterSubject = "Tervis Contractor Account Setup"
    $TervisContractorWelcomeLetter = @"
    $Name,
 
This email is to verify that your account has been setup correctly. This email should forward to your external mailbox.

To receive your credentials for our environment, please call the helpdesk at 941.441.3168.
 
Before logging in, you will be required to change your password by going to https://adfs.tervis.com/adfs/portal/updatepassword. This password must include at minimum 6 characters, 1 capital, 1 number, and must not include your name.
 
To install the Cisco VPN agent, navigate to https://ciscovpn.tervis.com. You will need to log in using the Tervis domain and username (i.e. tervis\myusername)
Remote Desktop and RemoteApps can be accessed by browsing to https://rdweb.tervis.com/rdweb via Internet Explorer. You will also be able to access our Sharepoint server with a VPN connection via the URL https://sharepoint.tervis.com

If you require any assistance interfacing with our infrastructure please feel free to call the helpdesk at 941.441.3168 or email tthelpdesk@tervis.com

Thanks,
Tervis IT
"@

    Send-MailMessage -To $EmailAddress -From "technicalservices@tervis.com" -Subject $TervisContractorWelcomeLetterSubject -Body $TervisContractorWelcomeLetter -SmtpServer cudaspam.tervis.com

}