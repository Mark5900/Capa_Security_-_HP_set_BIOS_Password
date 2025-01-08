[CmdletBinding()]
Param(
  [Parameter(Mandatory=$true)]
  [string]$Packageroot,
  [Parameter(Mandatory=$true)]
  [string]$AppName,
  [Parameter(Mandatory=$true)]
  [string]$AppRelease,
  [Parameter(Mandatory=$true)]
  [string]$LogFile,
  [Parameter(Mandatory=$true)]
  [string]$TempFolder,
  [Parameter(Mandatory=$true)]
  [string]$DllPath,
  [Parameter(Mandatory=$false)]
  [Object]$InputObject=$null
)
###################
#### VARIABLES ####
###################
$global:PlaintextPassword = '' # The BIOS password you want to set. If DecryptionKey and EncryptedPassword are set, this will be ignored.

# The decryption key for the password.
$global:DecryptionKey = '19,204,47,116,15,88,240,202,75,23,109,107,29,37,147,63,241,130,34,138,37,167,34,181,243,241,57,104,164,206,129,26'
# The encrypted password.
$global:EncryptedPassword = '76492d1116743f0423413b16050a5345MgB8AEgAbwBVAGoAcgBKAGkAKwAzAHMAMQBQAG4ARgA4AE4ATABlAE4AMgA5AEEAPQA9AHwANAA4ADkAMgBlADcAMAA5AGMAOAAxAGUAMgBkADUAZgBjADcAZQA3AGUAYgAwAGYANQA4ADYAYQA3AGIAZABhADkANQBlADAAZQA3ADEANgBlAGUAYgAzADcANAA3AGIAYQBlAGYANQBkAGIANwBlADMANwA5ADYAYQBhAGUANQBmADkANwA1ADMANwA3ADIAMgA0ADAAZQBkADYAYgA4AGQAMwBiADIAYgA0ADEAZAA4ADUAZQAxADYAYgA5ADQA'

# DO NOT CHANGE THESE VARIABLES
$global:ModuleVersion = '1.8.1'

$global:Packageroot = $Packageroot
$global:AppName = $AppName
$global:AppRelease = $AppRelease
$global:LogFile = $LogFile
$global:TempFolder = $TempFolder
$global:DllPath = $DllPath
$global:InputObject = $InputObject
[bool]$global:DownloadPackage = $true # Set to $true if you want to download the kit folder from the server

###################
#### FUNCTIONS ####
###################
function PreInstall {
	$cs.Log_SectionHeader('PreInstall', 'o')

	Import-Module (Join-Path $global:Packageroot 'kit' 'HP.Private' ) -Force
	Import-Module (Join-Path $global:Packageroot 'kit' 'HP.ClientManagement' $global:ModuleVersion 'HP.UEFI.psm1') -Force
	Import-Module (Join-Path $global:Packageroot 'kit' 'HP.ClientManagement') -Force
}

function Install {
	$cs.Log_SectionHeader('Install', 'o')

	if (Get-HPBIOSSetupPasswordIsSet) {
		$cs.Job_WriteLog('BIOS password is already set.')
	} else {
		$cs.Job_WriteLog('Setting BIOS password.')

		# Decrypting the password to plaintext
		if ($global:DecryptionKey -and $global:EncryptedPassword) {
			$SecureString = $global:EncryptedPassword | ConvertTo-SecureString -Key $global:DecryptionKey
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
			$global:PlaintextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
		}

		Set-HPBIOSSetupPassword -Password $global:PlaintextPassword
	}
}

function PostInstall {
  $cs.Log_SectionHeader("PostInstall",'o')
}

##############
#### MAIN ####
##############
try {
  ##############################################
  #load core PS lib - don't mess with this!
  if ($global:InputObject){$pgkit=""}else{$pgkit="kit"}
  Import-Module (Join-Path $global:Packageroot $pgkit "PSlib.psm1") -ErrorAction stop
  #load Library dll
  $cs=Add-PSDll
  ##############################################

  #Begin
  $cs.Job_Start("WS",$global:AppName,$global:AppRelease,$global:LogFile,"INSTALL")
  $cs.Job_WriteLog("[Init]: Starting package: '" + $global:AppName + "' Release: '" + $global:AppRelease + "'")
  if(!$cs.Sys_IsMinimumRequiredDiskspaceAvailable('c:',1500)){Exit-PSScript 3333}
  if ($global:DownloadPackage -and $global:InputObject){Start-PSDownloadPackage}

  $cs.Job_WriteLog("[Init]: `$PackageRoot:` '" + $global:Packageroot + "'")
  $cs.Job_WriteLog("[Init]: `$AppName:` '" + $global:AppName + "'")
  $cs.Job_WriteLog("[Init]: `$AppRelease:` '" + $global:AppRelease + "'")
  $cs.Job_WriteLog("[Init]: `$LogFile:` '" + $global:LogFile + "'")
  $cs.Job_WriteLog("[Init]: `$global:AppLogFolder:` '" + $global:AppLogFolder + "'")
  $cs.Job_WriteLog("[Init]: `$TempFolder:` '" + $global:TempFolder + "'")
  $cs.Job_WriteLog("[Init]: `$DllPath:` '" + $global:DllPath + "'")
  $cs.Job_WriteLog("[Init]: `$global:DownloadPackage`: '" + $global:DownloadPackage + "'")
  $cs.Job_WriteLog("[Init]: `$global:PSLibVersion`: '" + $global:PSLibVersion + "'")

  PreInstall
  Install
  PostInstall
  Exit-PSScript $Error
}
catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    $cs.Job_WriteLog("*****************","Something bad happend at line $($line): $($_.Exception.Message)")
    Exit-PSScript $_.Exception.HResult
}