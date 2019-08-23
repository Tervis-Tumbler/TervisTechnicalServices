#Requires -Modules TervisCUCM, TervisCUPI, CUCMPowerShell, TervisActiveDirectory, TervisMSOnline, TervisApplication

function Install-TervisTechnicalServices {
    Install-TervisMSOnline
    Install-TervisCUCM
    Install-TervisCUPI
    Invoke-EnvironmentVariablesRefresh
    Install-TervisTechnicalServicesWindowsServer
}

function New-TervisPerson {
    [cmdletbinding(DefaultParameterSetName="BusinessUser")]
    param(
        [ValidateSet("Employee","Contractor")]
        [Parameter(Mandatory)]
        $Type,

        [parameter(Mandatory)]$GivenName,
        [parameter(Mandatory)]$SurName,
        [parameter(Mandatory)]$ManagerSAMAccountName,

        [parameter(ParameterSetName="BusinessUser")]$Department,        
        $Title,
        
        [parameter(ParameterSetName="BusinessUser")]
        [parameter(Mandatory,ParameterSetName="Contractor")]
        $Company,

        [parameter(Mandatory,ParameterSetName="Contractor")]
        $ExternalEmailAddress,

        [parameter(Mandatory,ParameterSetName="BusinessUser")]$SAMAccountNameToBeLike,
        [parameter(ParameterSetName="BusinessUser")][switch]$UserHasTheirOwnDedicatedComputer,
        [parameter(ParameterSetName="BusinessUser")][switch]$UserHasMicrosoftTeamPhone,
        [parameter(ParameterSetName="BusinessUser")][switch]$ADUserAccountCreationOnly
    )
    process {
        $SAMAccountName = Get-AvailableSAMAccountName -GivenName $GivenName -Surname $SurName
        $FullName = "$GivenName $SurName"
        $SecurePW = (New-PasswordstatePassword -PasswordListId 78 -Title $FullName -Username $SAMAccountName -GeneratePassword) | 
        Select-Object -ExpandProperty Password | 
        ConvertTo-SecureString -AsPlainText -Force

        $TervisWindowsUserParameters = $PSBoundParameters |
        ConvertFrom-PSBoundParameters -Property GivenName, Surname, ManagerSAMAccountName, Department, Title, Company, SAMAccountNameToBeLike, UserHasTheirOwnDedicatedComputer, ADUserAccountCreationOnly, Type -AsHashTable

        New-TervisWindowsUser @TervisWindowsUserParameters -SAMAccountName $SAMAccountName -AccountPassword $SecurePW
        if ($UserHasMicrosoftTeamPhone) {
            New-TervisMicrosoftTeamPhone -UserID $SAMAccountName -LocationID "d99a1eb3-f053-448a-86ec-e0d515dc0dea"
        }

        if ($Type -eq "Contractor") {
            if ($null -eq (Get-ADGroup -Filter {SamAccountName -eq $Company})) {
                New-ADGroup -Name $Company -GroupScope Universal -GroupCategory Security
            }
            $CompanySecurityGroup = Get-ADGroup -Identity $Company
            
            Add-ADGroupMember $CompanySecurityGroup -Members $SAMAccountName
            Add-ADGroupMember "LongPWPolicy" -Members $SAMAccountName
            Import-TervisExchangePSSession
            New-ExchangeMailContact -FirstName $GivenName -LastName $SurName -Name $FullName -ExternalEmailAddress $ExternalEmailAddress
            Set-ADEmployeeNumberAttributeToThirtyCharacterGUID -Identity $SAMAccountName

            Send-TervisContractorWelcomeLetter -Name $FullName -EmailAddress $ExternalEmailAddress
        }
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
},
[PSCustomObject][Ordered] @{
    Name = "eComchain"
    RoleSecurityGroup = "eComchain"
},
[PSCustomObject][Ordered] @{
    Name = "QC Software"
    RoleSecurityGroup = "QC Software"
},
[PSCustomObject][Ordered] @{
    Name = "HeliosGroup"
    RoleSecurityGroup = "HeliosGroup"
},
[PSCustomObject][Ordered] @{
    Name = "KerkeringBarberio"
    RoleSecurityGroup = "KerkeringBarberio"
}


function Send-TervisContractorWelcomeLetter {
    param (
        [parameter(Mandatory)]$Name,
        [parameter(Mandatory)]$EmailAddress,
        $CcEmailAddress
    )

    $TervisContractorWelcomeLetterSubject = "Tervis Contractor Account Setup"
    $TervisContractorWelcomeLetter = @"
    $Name,
 
Your Tervis domain account has been created.

To receive your credentials for our environment, please call the helpdesk at 941.441.3168.
 
Before logging in, you will be required to change your password by going to https://adfs.tervis.com/adfs/portal/updatepassword. This page requires usernames in the format "tervis\username"
Note: We have moved to a longer, more secure password policy. We are now using passphrase based passwords consisting of multiple, random words creating one long, but memorable passphrase of at least 20 characters. 

To install the Cisco VPN agent, navigate to https://ciscovpn.tervis.com. You will need to log in using the Tervis domain credentials (only your username, no domain prefix). 
To configure two-factor authentication for VPN, please follow the steps in the three attached documents.

Remote Desktop and RemoteApps can be accessed by browsing to https://rdweb.tervis.com/rdweb via Internet Explorer.

You will need to log in using your Tervis username in the format of "Tervis\Username".

If you require any assistance interfacing with our infrastructure please feel free to call the helpdesk at 941.441.3168.

Thanks,
Tervis IT
"@

    if ($CcEmailAddress){
        Send-TervisMailMessage -To $EmailAddress -Cc $CcEmailAddress -From "TechnicalServices@tervis.com" -Subject $TervisContractorWelcomeLetterSubject -Body $TervisContractorWelcomeLetter -Attachments "$PSScriptRoot\1 - Import the Tervis Root CA.pdf","$PSScriptRoot\2 - Request and install the Vendor certificate through IE 11.pdf","$PSScriptRoot\3 - Set up Cisco AnyConnect to use new profile.pdf"
    } else {
        Send-TervisMailMessage -To $EmailAddress -From "TechnicalServices@tervis.com" -Subject $TervisContractorWelcomeLetterSubject -Body $TervisContractorWelcomeLetter -Attachments "$PSScriptRoot\1 - Import the Tervis Root CA.pdf","$PSScriptRoot\2 - Request and install the Vendor certificate through IE 11.pdf","$PSScriptRoot\3 - Set up Cisco AnyConnect to use new profile.pdf"    
    }
}

function Invoke-GPOStringSearch {
    param (
        [string]$SearchString
    )
    $GPOs = Get-GPO -All
    $i = 0
    $GPOs | ForEach-Object {
        Write-Progress -Activity "Searching for `"$SearchString`"" -Status $_.DisplayName -PercentComplete ($i * 100 / $GPOs.count)
        if ($_.GenerateReport([Microsoft.GroupPolicy.ReportType]::xml) -match $SearchString) {
            $_
        }
        $i++
    }
}

function Invoke-OutputFileToRemoteTempPath {
    param(
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$FileContent
    )
    process{
        $TempFilePath = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $TempFilePath = "$([io.path]::GetTempFileName()).xml"
            $using:FileContent | Out-File -FilePath $TempFilePath
            $TempFilePath
        }
        $TempFilePath
    }
}

function Set-ADEmployeeNumberAttributeToThirtyCharacterGUID{
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]$SamAccountName
    )
    [string]$UserGuid = Get-ADUser -Identity $SamAccountName -Properties ObjectGuid | Select-Object -ExpandProperty ObjectGuid
    $ContractorID = $UserGuid.Replace("-","").Substring(0,30)
    Set-ADUser -Identity $SamAccountName -EmployeeNumber $ContractorID
    Write-Verbose -Message "ContractorID: $ContractorID"
}

function Restart-BartenderLicensingServer{
    
    Send-TervisMailMessage -To TechnicalServices@tervis.com -Subject "Bartender Licensing System Rebooting" -From HelpDeskTeam@tervis.com -Body @"
Team,

The Bartender Licensing server, "Bartender.tervis.prv", is currently being rebooted.

Thanks,

IT
"@
    
Restart-Computer -ComputerName Bartender -Wait -Force

    Send-TervisMailMessage -To TechnicalServices@tervis.com -Subject "RE: Bartender Licensing System Rebooting" -From HelpDeskTeam@tervis.com -Body @"
Team,

The reboot of Bartender Licensing, "Bartender.tervis.prv", has completed.

Thanks,

IT
"@
}