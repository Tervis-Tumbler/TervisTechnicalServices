#Requires -Modules TervisCUCM, TervisCUPI, CUCMPowerShell, TervisActiveDirectory, TervisMSOnline, TervisApplication

function Install-TervisTechnicalServices {
    Install-TervisMSOnline
    Install-TervisCUCM
    Install-TervisCUPI
    Invoke-EnvironmentVariablesRefresh
    Install-TervisTechnicalServicesWindowsServer
}

function New-TervisPerson {
    param(
        [parameter(ParameterSetName="BusinessUser")][Switch]$Employee,
        [parameter(ParameterSetName="MESOnly")][Switch]$MESOnly,

        [parameter(Mandatory,ParameterSetName="BusinessUser")]
        [parameter(Mandatory,ParameterSetName="MESOnly",ValueFromPipelineByPropertyName)]
        $GivenName,

        [parameter(Mandatory,ParameterSetName="BusinessUser")]
        [parameter(Mandatory,ParameterSetName="MESOnly",ValueFromPipelineByPropertyName)]
        $SurName,

        [parameter(Mandatory,ParameterSetName="BusinessUser")]$ManagerSAMAccountName,
        [parameter(Mandatory,ParameterSetName="BusinessUser")]$Department,
        [parameter(Mandatory,ParameterSetName="BusinessUser")]$Title,
        [parameter(ParameterSetName="BusinessUser")]$Company = "Tervis",
        [parameter(Mandatory,ParameterSetName="BusinessUser")]$SAMAccountNameToBeLike,
        [parameter(ParameterSetName="BusinessUser")][switch]$UserHasTheirOwnDedicatedComputer
    )
    begin {
        $MESUsers = @()
    }
    process {
        $SAMAccountName = Get-AvailableSAMAccountName -GivenName $GivenName -Surname $SurName

        if ($Employee) {
            New-PasswordstatePassword -PasswordListId 78 -Title "$GivenName $SurName" -Username $SAMAccountName -GeneratePassword
            New-TervisWindowsUser -GivenName $GivenName -Surname $SurName -SAMAccountName $SAMAccountName -ManagerSAMAccountName $ManagerSAMAccountName -Department $Department -Title $Title -Company $Company -AccountPassword $SecurePW -SAMAccountNameToBeLike $SAMAccountNameToBeLike -UserHasTheirOwnDedicatedComputer:$UserHasTheirOwnDedicatedComputer
            New-TervisCiscoJabber -UserID $SAMAccountName
        }

        if ($MESOnly) {
            $MESUsers += [PSCustomObject]@{
                GivenName = $GivenName
                SurName = $SurName
                SAMAccountName = $SAMAccountName
            }
            New-TervisProductionUser -GivenName $GivenName -SurName $SurName -SAMAccountName $SAMAccountName -AccountPassword $SecurePW
        }
    }
    end {
        $MESUsers | Add-Member -MemberType ScriptProperty -Name ADUser -Value {
            Get-ADUser -Identity  $This.SAMAccountName
        }
        $MESUsers
    }
}

function Remove-TervisPerson {
    param(
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory, ParameterSetName="ManagerReceivesData")][Switch]$ManagerReceivesData,
        [Parameter(Mandatory, ParameterSetName="AnotherUserReceivesData")]$IdentityOfUserToReceiveData,
        [Parameter(Mandatory, ParameterSetName="NoUserReceivesData")][Switch]$NoUserReceivesData,
        [Switch]$UserWasITEmployee
    )
    $ADUser = Get-ADUser -Identity $Identity -Properties Manager

    if ($NoUserReceivesData) {
        $IdentityOfUserToReceiveData = $null
    }

    if ($ManagerReceivesData) {
        if( -not $ADUser.Manager) { 
            Throw "ManagerReceivesData was specified but the user doesn't have a manager in Active Directory" 
        }
        $IdentityOfUserToReceiveData = (Get-ADUser ($ADUser.Manager)).SamAccountName
    }        

    Invoke-TervisVOIPTerminateUser -SamAccountName $Identity -Verbose
    
    Remove-TervisMSOLUser -Identity $Identity -IdentityOfUserToReceiveAccessToRemovedUsersMailbox $IdentityOfUserToReceiveData
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
        ($EmailAddressToSHI = "kayla_reger@shi.com"),
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
    $ADuser = Get-TervisADUser -Identity $Identity -IncludeMailboxProperties

    if($ADuser.O365Mailbox) {
        Write-Output "The user account $Identity has an Office 365 mailbox.  Please run the function 'Remove-TervisUser' for this user."

    } elseif ($ADuser.ExchangeMailbox) {
        Write-Output "The user account $Identity has an On Premises Exchange 2016 mailbox.  Please contact their manager to see if they need access to the user's email."
    } else {
        Write-Output "User has no mailbox, removing user account."
        Remove-ADUser -Identity $Identity -Confirm
    }
}

function Send-EBSResponsibilityApprovalRequestEmail {
    param(
        [parameter(mandatory)]$EBSUsernameOfEmployeeNeedingEBSResponsibility,
        [parameter()]$EmailToCc = "helpdeskteam@tervis.com",
        [parameter()]$PathToMatrix = "\\$(Get-DomainName -ComputerName $env:COMPUTERNAME)\applications\PowerShell\EBSResponsibilityMatrix\EBSResponsibilityOwnerApproverMatrix.csv"
    )
    
    $Matrix = Import-Csv -Path $PathToMatrix
    $MatrixGridResponsibilities = $Matrix | Out-GridView -PassThru

    foreach ($EBSResponsibility in $MatrixGridResponsibilities){
        #$EBSResponsibility = Get-EBSResponsibility -ResponsibilityName $Responsibility -PathToMatrix $PathToMatrix
        $EBSResponsibilityApprover = $EBSResponsibility.Approver
        $EBSResponsibilityApproverEmail = $EBSResponsibility.ApproverEmail
        $EBSResponsibilityName = $EBSResponsibility.ResponsibilityName
        $EBSResponsibilitySpecialNote = $EBSResponsibility.SpecialNote

        if ($EBSResponsibilityApprover -ne "none") {
            $From = "helpdeskteam@tervis.com"
            $To = $EBSResponsibilityApproverEmail
            $Subject = "Approval of EBS Responsibility $EBSResponsibilityName for $EBSUsernameOfEmployeeNeedingEBSResponsibility"
            $Body = 
@"
$EBSResponsibilityApprover,

Do you approve of EBS user $EBSUsernameOfEmployeeNeedingEBSResponsibility having access to the following EBS responsibility?
$EBSResponsibilityName

$EBSResponsibilitySpecialNote

Thanks,

Help Desk
"@
            Send-TervisMailMessage -To $To -From $From -Subject $Subject -Body $Body -Cc $EmailToCc
        }
        elseif ($EBSResponsibilityApprover -eq "none") {
            $From = "helpdeskteam@tervis.com"
            $To = "helpdeskteam@tervis.com"
            $Subject = "Approval of EBS Responsibility $EBSResponsibilityName for $EBSUsernameOfEmployeeNeedingEBSResponsibility"
            $Body = 
@"
HelpDesk,

$EBSResponsibilityName requires no approval for user $EBSUsernameOfEmployeeNeedingEBSResponsibility.

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

function New-TervisProductionUsers {
    param(
        $PathToCSV = "\\$(Get-DomainName -ComputerName $env:COMPUTERNAME)\applications\PowerShell\New-TervisProductionUsers\TervisProductionUsers.csv"
    )
    $TervisProductionUsers = Import-Csv -Path $PathToCSV
    $TervisProductionUsers | New-TervisPerson -MESOnly
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
},
[PSCustomObject][Ordered] @{
    Name = "Fadel"
    RoleSecurityGroup = "Fadel"
}

function Send-TervisContractorWelcomeLetter {
    param (
        [parameter(Mandatory)]$Name,
        [parameter(Mandatory)]$EmailAddress
    )

    $TervisContractorWelcomeLetterSubject = "Tervis Contractor Account Setup"
    $TervisContractorWelcomeLetter = @"
    $Name,
 
Your Tervis domain account has been created.

To receive your credentials for our environment, please call the helpdesk at 941.441.3168.
 
Before logging in, you will be required to change your password by going to https://adfs.tervis.com/adfs/portal/updatepassword. This password must include at minimum 6 characters, 1 capital, 1 number, and must not include your name.
NOTE: In this screen, you must enter your username in the format "tervis\username"
 
To install the Cisco VPN agent, navigate to https://ciscovpn.tervis.com. You will need to log in using the Tervis domain credentials (only your username, no domain prefix). 
To configure two-factor authentication for VPN, please follow the steps in the three attached documents.

Remote Desktop and RemoteApps can be accessed by browsing to https://rdweb.tervis.com/rdweb via Internet Explorer. You will also be able to access our Sharepoint server with a VPN connection via the URL https://sharepoint.tervis.com.
You will need to log in using your Tervis username in the format of "Tervis\Username".

If you require any assistance interfacing with our infrastructure please feel free to call the helpdesk at 941.441.3168 or email tthelpdesk@tervis.com

Thanks,
Tervis IT
"@

    Send-MailMessage -To $EmailAddress -From "technicalservices@tervis.com" -Subject $TervisContractorWelcomeLetterSubject -Body $TervisContractorWelcomeLetter -SmtpServer cudaspam.tervis.com -Attachments "$PSScriptRoot\1 - Import the Tervis Root CA.pdf","$PSScriptRoot\2 - Request and install the Vendor certificate through IE 11.pdf","$PSScriptRoot\3 - Set up Cisco AnyConnect to use new profile.pdf"

}