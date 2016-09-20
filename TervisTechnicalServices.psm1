#Requires -Modules TervisCUCM, TervisCUPI, CUCMPowerShell

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
        [ValidateSet("CallCenterAgent")]$UserType,
        $UserID
    )

    if ($UserType -eq "CallCenterAgent") {
        $Pattern = Find-CUCMLine -Pattern 7% -Description "" | select -First 1
        Set-ADUser $UserID -OfficePhone $Pattern
        Sync-CUCMtoLDAP

        do {
            sleep -Seconds 3
        } until (Get-CUCMUser -UserID $UserID -ErrorAction SilentlyContinue)

        $ADUser = Get-ADUser $UserID
        $DisplayName = $ADUser.name

        Set-CUCMLine -Pattern $Pattern -RoutePartitionName UCCX_PT -Description $DisplayName -AlertingName $DisplayName -AsciiAlertingName $DisplayName 

    }
}