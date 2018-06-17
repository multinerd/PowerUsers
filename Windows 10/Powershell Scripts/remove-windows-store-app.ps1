﻿Function PSCustomErrorRecord
{
	Param
	(		
		[Parameter(Mandatory=$true,Position=1)][String]$ExceptionString,
		[Parameter(Mandatory=$true,Position=2)][String]$ErrorID,
		[Parameter(Mandatory=$true,Position=3)][System.Management.Automation.ErrorCategory]$ErrorCategory,
		[Parameter(Mandatory=$true,Position=4)][PSObject]$TargetObject
	)
	Process
	{
		$exception = New-Object System.Management.Automation.RuntimeException($ExceptionString)
		$customError = New-Object System.Management.Automation.ErrorRecord($exception,$ErrorID,$ErrorCategory,$TargetObject)
		return $customError
	}
}
	
Function RemoveAppxPackage
{
	$index=1
	$apps=Get-AppxPackage -AllUsers

	Write-Host "ID`t App name"
	foreach ($app in $apps)
	{
		Write-Host " $index`t $($app.name)"
		$index++
	}
    
    Do
    {
        $IDs=Read-Host -Prompt "Which Apps do you want to remove? `nInput their IDs and seperate IDs by comma"
    }
    While($IDs -eq "")
    

	try
	{	
		[int[]]$IDs=$IDs -split ","
	}
	catch
	{
		$errorMsg = $Messages.IncorrectInput
		$errorMsg = $errorMsg -replace "Placeholder01",$IDs
		$customError = PSCustomErrorRecord `
		-ExceptionString $errorMsg `
		-ErrorCategory NotSpecified -ErrorID 1 -TargetObject $pscmdlet
		$pscmdlet.WriteError($customError)
		return
	}

	foreach ($ID in $IDs)
	{
		if ($ID -ge 1 -and $ID -le $apps.count)
		{
			$ID--
			$AppName=$apps[$ID].name

			Remove-AppxPackage -Package $apps[$ID] -ErrorAction SilentlyContinue
			if (-not(Get-AppxPackage -Name $AppName))
			{
				Write-host "$AppName has been removed successfully"
			}
			else
			{
				Write-Warning "Remove '$AppName' failed! This app is part of Windows and cannot be uninstalled on a per-user basis."
			}
		}
		else
		{
			$errorMsg = $Messages.WrongID
			$errorMsg = $errorMsg -replace "Placeholder01",$ID
			$customError = PSCustomErrorRecord `
			-ExceptionString $errorMsg `
			-ErrorCategory NotSpecified -ErrorID 1 -TargetObject $pscmdlet
			$pscmdlet.WriteError($customError)
		}
	}
}

RemoveAppxPackage
