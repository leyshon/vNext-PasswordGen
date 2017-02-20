Function New-Password { 
 
    [CmdletBinding()] 
    [OutputType([String])] 
 
     
    Param( 
 
        [int]$length=32, 
 
        [alias("U")] 
        [Switch]$Uppercase, 
 
        [alias("L")] 
        [Switch]$LowerCase, 
 
        [alias("N")] 
        [Switch]$Numeric, 
 
        [alias("S")] 
        [Switch]$Symbolic 
 
    ) 
 
        
    If ($Uppercase) {$CharPool += ([char[]](64..90))} 
    If ($LowerCase) {$CharPool += ([char[]](97..122))} 
    If ($Numeric) {$CharPool += ([char[]](48..57))} 
    If ($Symbolic) {$CharPool += ([char[]](33..47))}

         
    If ($CharPool -eq $null) { 
        Throw 'You must select at least one of the parameters "Uppercase" "LowerCase" "Numeric" or "Symbolic"' 
    } 
 
    [String]$Password =  (Get-Random -InputObject $CharPool -Count $length) -join '' 
         
    return $Password 
     
}

Function New-AzureSecret {
    [CmdletBinding()]
    Param(
        [string]$SecretName,
        [string]$Username,
        [string]$VaultName,
        [int]$PasswordLength=32,
        [alias("N")]
        [Switch]$IncludeNumeric=$true,
        [alias("S")]
        [Switch]$IncludeSymbols=$true,
        [alias("U")]
        [Switch]$IncludeUpperCase=$true,
        [alias("L")]
        [Switch]$IncludeLowerCase=$true
    )    

    $Secrets = Get-AzureKeyVaultSecret -VaultName $VaultName
    if ($Secrets.name -notcontains $SecretName) {
        Write-Verbose "Creating new secret '$SecretName'"
        $Tags = @{Username = $Username}
        $Password = ConvertTo-SecureString -String (New-Password -Length $PasswordLength -U:$U -L:$L -N:$N -S:$S) -AsPlainText -Force
        Set-AzureKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $Password -Tags $Tags | Out-Null
    }
    else {
        Write-Verbose "Secret '$SecretName' already exists"
    }
}

# Get the values
$SecretName = Get-VstsInput -Name SecretName -Require
$Username = Get-VstsInput -Name Username -Require 
$VaultName = Get-VstsInput -Name VaultName -Require
$Length = Get-VstsInput -Name PasswordLength -Require
$N = Get-VstsInput -Name Numeric -Require -AsBool
$S = Get-VstsInput -Name Symbols -Require -AsBool
$U = Get-VstsInput -Name Upper -Require -AsBool
$L = Get-VstsInput -Name Lower -Require -AsBool


# Initialize Azure
Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_
Initialize-Azure

New-AzureSecret -SecretName $SecretName -Username $Username -VaultName $VaultName -PasswordLength $Length -N:$N -S:$S -U:$U -L:$L
