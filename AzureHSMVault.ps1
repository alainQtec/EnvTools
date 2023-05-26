#!/usr/bin/env pwsh
#region    Classes
class IDVault {
    IDVault() {
        # $creds = ([IO.File]::ReadAllText((Get-Item .\creds.yml).FullName) | ConvertFrom-Yaml).creds
    }
}
enum AzureLocation {
    # I only included avaliable locations for KeyVault/managedHSMs
    eastus2
    southcentralus
    northeurope
    westeurope
    canadacentral
    centralus
    switzerlandnorth
    southafricanorth
    uksouth
    southeastasia
    eastasia
    koreacentral
    australiacentral
    westus
    eastus
    northcentralus
    westcentralus
    westus2
    westus3
    canadaeast
    japaneast
    uaenorth
    australiaeast
    francecentral
    switzerlandwest
    centralindia
    brazilsouth
    swedencentral
    qatarcentral
    southindia
    polandcentral
    japanwest
    norwayeast
}

#region    HsmVault
# .SYNOPSIS
#  HsmVault is a class to Interact with Azure Key Vault's Managed HSM (Hardware Security Module).
# .DESCRIPTION
#  This class to interact with the Azure Key Vault's Managed HSM service. You can use it to create, read, update, and delete keys and secrets stored in the HSM.
#  I mainly use it to Retrieve AES Keys from Azure Key Vault. ie: https://www.gavsto.com/msp-powershell-for-beginners-part-2-securely-store-credentials-passwords-api-keys-and-secrets/
# .EXAMPLE
# $hsmCl = [HsmVault]::new()
# .NOTES
# If you do not have an Azure subscription, create a [free account](https://azure.microsoft.com/free/?WT.mc_id=A261C142F) before using this class.
# Make sure your .env file has the following keys not empty:
# ```yaml
# - AzureServicePrincipalAppName = Envtools
# - AzureSubscriptionName        = # Create your Az Subscription : 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/SubscriptionCreateBlade' # AZURE SUBSCRIPTION NAME FORMAT: <Company>-<Department>-sub-<Environment>
# - AzureSubscriptionID          = # GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
# - AzureResourceGroup           = # Name Your ResGroup
# - AzureVaultName               = # Name the vault to use
# - AzureTenantID                = # GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
# - CertName                     = Envtools-cert
# - hsmName                      = Envtools-Hsm
# - keyName                      = Envtools-Key
# - Email                        = # your azure Email
# ```
#  Your_Key_Vault                = 'https://azure.microsoft.com/en-us/services/key-vault/'
class HsmVault {
    [AzConfig] $config
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    static hidden [string]$VarName_Suffix = '7fb2e877_6c2b_406a_af40_e1d915c62cdf'
    static hidden $X509CertHelper

    HsmVault() {
        $this.config = [AzConfig]::New(); $this.Setup()
        $this.Cert = [HsmVault]::X509CertHelper::CreateSelfSignedCertificate("CN=$($this.config.CertName)");
        $this.Authenticate();
    }
    HsmVault([string]$AzureVaultName, [AzureResourceGroup]$AzureResourceGroup, [string]$AzureSubscriptionID) {
        $this.config = [AzConfig]::New(); $this.Setup();
        $this.Config.AzureVaultName = $AzureVaultName
        $this.Config.AzureResourceGroup = $AzureResourceGroup
        $this.Config.AzureSubscriptionID = $AzureSubscriptionID
        $this.Cert = [HsmVault]::X509CertHelper::CreateSelfSignedCertificate("CN=$($this.config.CertName)");
        $this.Authenticate();
    }
    [void] Authenticate() {
        [HsmVault]::SetSessionCreds($this.GetSessionId())
        $null = [HsmVault]::RunAsync({ Login-AzAccount }, 'AzAccount login')
        Write-Host "[HsmVault] Azure account Authentication complete." -ForegroundColor Green
    }
    [void] Setup() {
        if ([bool][int]$env:Is_HsmVault_Setup) { return };
        Write-Host '[HsmVault] Setting up an Azure Key Vault (One time only) ...' -ForegroundColor Green
        # https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-powershell
        [HsmVault]::Resolve_modules([string[]]('Az.Accounts', 'Az.Resources', 'Az.KeyVault'))
        [HsmVault]::Resolve_AzCli(); $AzureProfile = ConvertFrom-Json -InputObject $(az login) # same as: Connect-AzAccount
        if ($null -eq $AzureProfile) { throw "Failed to connect azureAccount" }
        # Checks:
        # $AzureProfile[1].user.name  -should be $AzConfig.Email.Address
        # $AzureProfile[1].name       -should be $AzConfig.AzureSubscriptionName
        Write-Host 'Enable Aliases from the previous Azure RM' -ForegroundColor Green
        Enable-AzureRmAlias -Scope CurrentUser; $AzConfig = $this.config
        $Location = $AzConfig.AzureResourceGroup.Location.ToString()
        $null = [HsmVault]::RunAsync({
                Set-AzContext -Subscription $AzConfig.AzureSubscriptionName; az account set --subscription $AzConfig.AzureSubscriptionName
                if ($(try { ![bool](Get-AzResourceGroup -Name $AzConfig.AzureResourceGroup.Name -ErrorAction SilentlyContinue) } catch { if ($_.exception.message -like "*Provided resource group does not exist*") { $true } else { throw $_ } })) {
                    $resGroup = $(az group create --name $AzConfig.AzureResourceGroup.Name --location $Location --tags Usecase=EnvTools) | ConvertFrom-Json
                    #Same as: New-AzResourceGroup -Name $AzConfig.AzureResourceGroup.Name -Location $Location -Tag @{ Usecase="EnvTools" } -Verbose
                    if (!$resGroup.properties.provisioningState.Equals("Succeeded")) { throw "Failed to create ResourceGroup" }
                }; Write-Host "Using ResourceGroup Name : '$($AzConfig.AzureResourceGroup.Name)'" -ForegroundColor Green
            }, 'Set resource Group'
        )
        if ($(az keyvault check-name --name $AzConfig.hsmName | ConvertFrom-Json).reason.Equals("AlreadyExists")) {
            Write-Host "Using KeyVault $($AzConfig.hsmName)" -ForegroundColor Green
        } else {
            Write-Host '[HsmVault] Creating a managed HSM ...' -ForegroundColor Green
            $null = Update-AzConfig -DisplayBreakingChangeWarning $false
            $AzObjectId = $(Get-AzADUser -Filter "startsWith(UserPrincipalName,'$($AzConfig.Email.Address.Replace('@','_'))')").Id
            $ManagedHsm = $(az keyvault create --hsm-name $AzConfig.hsmName --resource-group $AzConfig.AzureResourceGroup.Name --location $Location --administrators $AzObjectId --retention-days 90) | ConvertFrom-Json
            if ($null -ne $ManagedHsm) {
                Write-Host $ManagedHsm.properties.statusMessage -ForegroundColor Green
                if ($ManagedHsm.properties.provisioningState.Equals("Succeeded")) {
                    Write-Host "Keyvault url: $($ManagedHsm.properties.hsmUri)" -ForegroundColor Green
                }
            }
        }
        Write-Host "[HsmVault] Generate a certificate locally which will be used to Authenticate" -ForegroundColor Green
        $X509cert = [HsmVault]::CreateSelfSignedCertificate([AzConfig]$AzConfig, $this.GetSessionId().ToString());
        $keyValue = [System.Convert]::ToBase64String($X509cert.GetRawCertData())

        $sp = [HsmVault]::RunAsync({
                New-AzADServicePrincipal -DisplayName $AzConfig.AzureServicePrincipalAppName -CertValue $keyValue -StartDate $X509cert.NotBefore -EndDate $X509cert.NotAfter
                do {
                    Write-Host "`nWaiting for the service principal to propagate ..."
                    Start-Sleep -Milliseconds 1800
                } until ($null -ne (Get-AzADServicePrincipal -DisplayName $AzConfig.AzureServicePrincipalAppName))
                Get-AzSubscription -SubscriptionName $AzConfig.AzureSubscriptionName
            },
            'Generate a service principal'
        )
        $null = $AzConfig.Set('ApplicationId', $sp.Id)
        $null = [HsmVault]::RunAsync({ New-AzRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $sp.Name -ResourceGroupName $AzConfig.AzureResourceGroup.Name -ResourceType "Microsoft.KeyVault/vaults" -ResourceName $AzConfig.hsmName }, 'Assign the appropriate role to the service principal ...')
        $null = [HsmVault]::RunAsync({ Set-AzKeyVaultAccessPolicy -VaultName $AzConfig.hsmName -ObjectId $sp.Id -PermissionsToSecrets Get, Set }, 'Set the appropriate access to the secrets for the application ...')

        Set-Item -Path ([IO.Path]::Combine('Env:', 'Is_HsmVault_Setup')) -Value 1 -Force
        Write-Host ''
        Write-Host -ForegroundColor Blue "Tenant ID: $($AzConfig.AzureTenantID)"
        Write-Host -ForegroundColor Blue "Application ID: $($AzConfig.ApplicationId)"
        Write-Host -ForegroundColor Blue "Azure Key Vault Name: $($AzConfig.hsmName)"
        Write-Host -ForegroundColor Blue "Certificate Subject Name: 'CN=ImpactKeyVault'"
        Disconnect-AzAccount
    }
    [HsmKey] GetKey([string]$keyName) {
        # Construct the request URL
        $url = "https://$($this.Config.AzureVaultName).managedhsm.azure.net/keys/$($keyName)?api-version=2021-04-01"

        # Make the API request
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Authorization" = "Bearer $(Get-AzAccessToken -ResourceUrl $([string]::Concat('https://', $($this.Config.AzureVaultName, '.managedhsm.azure.net')))).Token" } -Method GET

        # Create a HsmKey object from the response
        $key = [HsmKey]::new()
        $key.KeyName = $response.name
        $key.KeyType = $response.kty
        $key.KeyOperations = $response.key_ops
        $key.Key = $response.key
        return $key
    }
    [HsmSecret] GetSecret([string]$secretName) {
        # Construct the request URL
        $url = "https://$($this.Config.AzureVaultName).managedhsm.azure.net/secrets/$($secretName)?api-version=2021-04-01"

        # Make the API request
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Authorization" = "Bearer $(Get-AzAccessToken -ResourceUrl https://$($this.Config.AzureVaultName).managedhsm.azure.net).Token" } -Method GET
        # Create a HsmSecret object from the response
        $secret = [HsmSecret]::new()
        $secret.SecretName = $response.name
        $secret.Value = $response.value
        return $secret
    }
    [HsmKeyOperationResult] Decrypt([string]$keyName, [byte[]]$data) {
        # Construct the request URL
        $url = "https://$($this.Config.AzureVaultName).managedhsm.azure.net/keys/$keyName/decrypt?api-version=2021-04-01"

        # Construct the request body
        $body = @{
            "alg"   = "RSA1_5"
            "value" = [Convert]::ToBase64String($data)
        }
        # Make the API request
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Authorization" = "Bearer $(Get-AzAccessToken -ResourceUrl https://$($this.Config.AzureVaultName).managedhsm.azure.net).Token" } -Method POST -Body (ConvertTo-Json $body)

        # Create a HsmKeyOperationResult object from the response
        $result = [HsmKeyOperationResult]::new()
        $result.Result = [Convert]::FromBase64String($response.result)
        return $result
    }
    [HsmSecretOperationResult] SetSecret([string]$secretName, [string]$value) {
        # Construct the request URL
        $url = "https://$($this.Config.AzureVaultName).managedhsm.azure.net/secrets/$($secretName)?api-version=2021-04-01"
        # Construct the request body
        $body = @{
            "value" = $value
        }
        # Make the API request
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Authorization" = "Bearer $(Get-AzAccessToken -ResourceUrl https://$($this.Config.AzureVaultName).managedhsm.azure.net).Token" } -Method PUT -Body (ConvertTo-Json $body)

        # Create a HsmSecretOperationResult object from the response
        $result = [HsmSecretOperationResult]::new()
        $result.SecretName = $response.name
        $result.Version = $response.version
        return $result
    }
    static [System.Object[]] RunAsync([scriptBlock]$command, [string]$StatusMsg) {
        # .SYNOPSIS
        #  Run Commands using Background Runspaces Instead of PSJobs For Better Performance
        $Comdresult = $null; [ValidateNotNullOrEmpty()][scriptBlock]$command = $command
        $PsInstance = [System.Management.Automation.PowerShell]::Create().AddScript($command)
        $job = $PsInstance.BeginInvoke();
        do {
            $ProgressPercent = if ([int]$job.TotalTime.TotalMilliseconds -ne 0) { [int]($job.RemainingTime.TotalMilliseconds / $job.TotalTime.TotalMilliseconds * 100) } else { 100 }
            Write-Progress -Activity "[HsmVault]" -Status "$StatusMsg" -PercentComplete $ProgressPercent
            Start-Sleep -Milliseconds 100
        } until ($job.IsCompleted)
        Write-Progress -Activity "[HsmVault]" -Status "command Complete." -PercentComplete 100
        if ($null -ne $PsInstance) {
            $Comdresult = $PsInstance.EndInvoke($job);
            $PsInstance.Dispose(); $PsInstance.Runspace.CloseAsync()
        }
        return $Comdresult
    }
    static [void] SetSessionCreds([guid]$sessionId) {
        [HsmVault]::SetSessionCreds([guid]$sessionId, $false)
    }
    static [void] SetSessionCreds([guid]$sessionId, [bool]$Force) {
        if (![string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable("$sessionId"))) { if (!$Force) { return } }
        [System.Environment]::SetEnvironmentVariable("$sessionId", $((Get-Credential -Message "Enter your Pfx Password" -Title "-----[[ PFX Password ]]-----" -UserName $env:username).GetNetworkCredential().SecurePassword | ConvertFrom-SecureString), [EnvironmentVariableTarget]::Process)
    }
    hidden [void] Createkey([string]$keyName) {
        Write-Host "[HsmVault] Creating HSM key ..." -ForegroundColor Green
        Add-AzKeyVaultKey -HsmName $this.config.hsmName -Name $keyName -Destination HSM
    }
    [object] CreateSecret() {
        $private:secretvalue = $this::ConvertToSecureString('mySUPERsecretAPIkey!')
        $secret = Set-AzKeyVaultSecret -VaultName 'YourMSP-CredsKeyVault' -Name 'ExamplePassword' -SecretValue $secretvalue
        return $secret
    }
    [Byte[]] RetrieveKey() {
        $keyName = $this.config.keyName; [ValidateNotNullOrEmpty()][string]$keyName = $keyName
        return $this.RetrieveKey($keyName)
    }
    [string] RetrieveSecret() {
        # .EXAMPLE
        # $AdminUser = Get-AzKeyVaultSecret -VaultName $this.config.AzureVaultName -Name $AdminUserName
        # $AdminPass = Get-AzKeyVaultSecret -VaultName $this.config.AzureVaultName -Name $AdminPassword
        # $mycred = New-Object System.Management.Automation.PSCredential ("$($AdminUser.SecretValueText)", $AdminPass.SecretValue)
        $ApplicationId = (Get-AzADUser -UserPrincipalName $this.config.Email.Address).Id
        $this.Cert.Thumbprint = $this::X509CertHelper::GetThumbPrint($this.Cert.Subject, $this.config.AzureTenantID + '-cert')
        Connect-AzAccount -ServicePrincipal -CertificateThumbprint $this.Cert.Thumbprint -ApplicationId $ApplicationId -TenantId $this.Config.AzureTenantID
        $Secret = (Get-AzKeyVaultSecret -VaultName $this.config.AzureVaultName -Name "ExamplePassword").SecretValueText
        return $Secret
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateSelfSignedCertificate([AzConfig]$AzConfig, [string]$sessionId) {
        [HsmVault]::SetSessionCreds([guid]$sessionId)
        $X509VarName = "X509CertHelper_class_$([HsmVault]::VarName_Suffix)";
        if (!$(Get-Variable $X509VarName -ValueOnly -Scope script -ErrorAction Ignore)) {
            Write-Verbose "Fetching X509CertHelper class (One-time only)" -Verbose;
            Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/d8f277f1d830882c4927c144a99b70cd).files.'X509CertHelper.ps1'.content)));
        }
        $X509CertHelper_class = Get-Variable $X509VarName -ValueOnly -Scope script
        if ($X509CertHelper_class) { . $X509CertHelper_class; [HsmVault]::X509CertHelper = New-Object X509CertHelper }
        $Password = [System.Environment]::GetEnvironmentVariable($sessionId) | ConvertTo-SecureString
        return [HsmVault]::X509CertHelper::CreateSelfSignedCertificate("CN=$($AzConfig.CertName)", $AzConfig.PrivateCertFile, $Password, 2048, [System.DateTimeOffset]::Now.AddDays(-1).DateTime, [System.DateTimeOffset]::Now.AddDays($AzConfig.CertExpirationDays).DateTime)
    }
    [guid] GetSessionId() {
        return [HsmVault]::GetSessionId($this)
    }
    static [guid] GetSessionId($HsmVault) {
        # .NOTES
        # - Creates fake guids, that are mainly used to create unique object names with a little bit of info added.
        $hash = $HsmVault.GetHashCode().ToString()
        return [guid]::new([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes(([string]::Concat(([char[]](97..102 + 65..70) | Get-Random -Count (16 - $hash.Length))) + $hash))).Replace("-", "").ToLower().Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"))
    }
    static [bool] VerifyGetSessionId([guid]$guid, $HsmVault) {
        return $HsmVault.GetHashCode() -match $([string]::Concat([System.Text.Encoding]::UTF8.GetString($( {
                            param([string]$HexString)
                            $outputLength = $HexString.Length / 2;
                            $output = [byte[]]::new($outputLength);
                            $numeral = [char[]]::new(2);
                            for ($i = 0; $i -lt $outputLength; $i++) {
                                $HexString.CopyTo($i * 2, $numeral, 0, 2);
                                $output[$i] = [Convert]::ToByte([string]::new($numeral), 16);
                            }
                            return $output;
                        }.Invoke($guid.ToString().Replace('-', ''))
                    )
                ).ToCharArray().Where({ $_ -as [int] -notin (97..102 + 65..70) })
            )
        )
    }
    static [bool] VerifyGetSessionId([string]$guid, $Source) {
        return [HsmVault]::VerifyGetSessionId([guid]$guid, $Source)
    }
    [Byte[]] RetrieveKey([string]$keyName) {
        return (Get-AzKeyVaultKey -HsmName $this.config.hsmName -Name $keyName)
    }
    static [securestring] ConvertToSecureString([string]$plainText) {
        $private:Sec = $null; Set-Variable -Name Sec -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        $plainText.toCharArray().forEach({ [void]$Sec.AppendChar($_) }); $Sec.MakeReadOnly()
        return $Sec
    }
    static hidden [void] Resolve_AzCli() {
        if (!(Get-Command az -CommandType Application -ErrorAction SilentlyContinue)) {
            $hostOs = [HsmVault]::GetHostOs()
            if ($hostOs -eq "Linux") {
                Write-Host "Running az debian Installer" -ForegroundColor  Green
                [scriptblock]::Create('curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash').Invoke();
            } elseif ($hostOs -eq "MacOs") {
                Write-Host "Running az MacOs Installer" -ForegroundColor  Green
                [scriptblock]::Create('brew update && brew install azure-cli').Invoke();
            } elseif ($hostOs -eq "Windows") {
                Write-Host "Running az Windows Installer" -ForegroundColor  Green
                Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi;
                Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi
                #Same as: winget install -e --id Microsoft.AzureCLI
                [HsmVault]::refreshEnv()
            } else {
                throw "Host os is '$hostOs'!"
            }
        } else {
            Write-Verbose "Az Cli is already Installed"
        }
    }
    static hidden [void] refreshEnv() {
        $refrshrVarName = "refrshr_script_$([HsmVault]::VarName_Suffix)";
        if (!$(Get-Variable $refrshrVarName -ValueOnly -Scope script -ErrorAction Ignore)) {
            Set-Variable -Name $refrshrVarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/8b4ddc0302a9262cf7fc25e919227a2f).files.'Update_Session_Env.ps1'.content));
        }
        $refrshr_script = Get-Variable $refrshrVarName -ValueOnly -Scope script
        if ($refrshr_script) {
            Write-Host '[HsmVault] refreshing this Session Environment ...' -ForegroundColor Green
            . $refrshr_script; Update-SessionEnvironment
        } else {
            throw "Failed to fetch refresher script!"
        }
    }
    static hidden [void] Resolve_modules([string[]]$Names) {
        $varName = "resolver_script_$([HsmVault]::VarName_Suffix)";
        if (!$(Get-Variable $varName -ValueOnly -Scope script -ErrorAction Ignore)) {
            # Fetch it Once only, To Avoid spamming the github API :)
            Set-Variable -Name $varName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/7629f35f93ae89a525204bfd9931b366).files.'Resolve-Module.ps1'.content)))
        }
        $resolver_script = Get-Variable $varName -ValueOnly -Scope script
        if ($resolver_script) {
            . $resolver_script; Resolve-module -Name $Names
        } else {
            throw "Failed to fetch resolver script!"
        }
    }
    static hidden [string] GetHostOs() {
        return $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
    }
}
#endregion HsmVault

# .SYNOPSIS
# HsmKey
# .DESCRIPTION
# This class represents a key stored in the Azure Key Vault Managed HSM. You can use it to perform cryptographic operations like encryption and decryption.
class HsmKey {
    [string] $Name
    [string] $Type # (e.g. RSA, EC).
    [string] $CurveName # The name of the elliptic curve used for EC keys.
    [int] $KeySize
    [string] $KeyOps
    [string] $KeyAttributes # The attributes of the key (e.g. enabled, notBefore, expires).

    HsmKey([string]$name, [string]$type, [string]$curveName, [int]$keySize, [string]$keyOps, [string]$keyAttributes) {
        $this.Name = $name
        $this.Type = $type
        $this.CurveName = $curveName
        $this.KeySize = $keySize
        $this.KeyOps = $keyOps
        $this.KeyAttributes = $keyAttributes
    }
}

# .SYNOPSIS
# HsmSecret Class
# .DESCRIPTION
# This class represents a key stored in the Azure Key Vault Managed HSM. You can use it to perform cryptographic operations like encryption and decryption.
class HsmSecret {
    [string] $Name
    [string] $ContentType
    [string] $SecretAttributes

    HsmSecret([string]$name, [string]$contentType, [string]$secretAttributes) {
        $this.Name = $name
        $this.ContentType = $contentType
        $this.SecretAttributes = $secretAttributes
    }
}

# .SYNOPSIS
# HsmKeyOperationResult Class
# .DESCRIPTION
# This class represents the result of a cryptographic operation performed on a key in the Azure Key Vault Managed HSM.
class HsmKeyOperationResult {
    [SecureString] $Key
    [string] $aAlgorithm
    [string] $Operation
    [string] $Result
    [string] $Message

    HsmKeyOperationResult([string]$key, [string]$aAlgorithm, [string]$operation, [string]$result, [string]$message) {
        $this.Key = [HsmVault]::ConvertToSecureString($key)
        $this.Algorithm = $aAlgorithm
        $this.Operation = $operation
        $this.Result = $result
        $this.Message = $message
    }
}


# .SYNOPSIS
# HsmSecretOperationResult Class
# .DESCRIPTION
# This class represents the result of an operation performed on a secret in the Azure Key Vault Managed HSM.
class HsmSecretOperationResult {
    [string] $Secret
    [string] $Operation
    [string] $Result
    [string] $Message

    HsmSecretOperationResult([string]$secret, [string]$operation, [string]$result, [string]$message) {
        $this.Secret = $secret
        $this.Operation = $operation
        $this.Result = $result
        $this.Message = $message
    }
}

class AzureResourceGroup {
    [string] $Name
    [AzureLocation] $Location

    AzureResourceGroup([string]$Name) {
        $this.Name = $Name
        $this.Location = [AzureLocation]::uksouth
    }
    AzureResourceGroup([string]$name, [AzureLocation]$location) {
        $this.Name = $name
        $this.Location = $location
    }
    [string]ToString() {
        return $this.Name
    }
}

class Email {
    [string] $Address

    Email([string]$address) {
        if ($address -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
            $this.Address = $address
        } else {
            throw [System.IO.InvalidDataException]::New('Invalid email address.')
        }
    }
    [string]ToString() {
        return $this.Address
    }
}

class CfgList {
    CfgList() {
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
    }
    CfgList([hashtable[]]$array) {
        $this.Add($array)
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
    }
    [void] Add([string]$key, [System.Object]$value) {
        [ValidateNotNullOrEmpty()][string]$key = $key
        if (!$this.Contains($key)) {
            $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
        } else {
            Write-Warning "CfgList.Add() Skipped $Key. Key already exists."
        }
    }
    [void] Add([hashtable]$table) {
        [ValidateNotNullOrEmpty()][hashtable]$table = $table
        $Keys = $table.Keys | Where-Object { !$this.Contains($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
        foreach ($key in $Keys) { $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] }
    }
    [void] Add([hashtable[]]$items) {
        foreach ($item in $items) { $this.Add($item) }
    }
    [void] Add([System.Collections.Generic.List[hashtable]]$items) {
        foreach ($item in $items) { $this.Add($item) }
    }
    [void] Set([string]$key, [System.Object]$value) {
        $htab = [hashtable]::new(); $htab.Add($key, $value)
        $this.Set($htab)
    }
    [void] Set([hashtable]$item) {
        $Keys = $item.Keys | Sort-Object -Unique
        foreach ($key in $Keys) {
            $value = $item[$key]
            [ValidateNotNullOrEmpty()][string]$key = $key
            [ValidateNotNullOrEmpty()][System.Object]$value = $value
            if ($this.psObject.Properties.Name.Contains([string]$key)) {
                $this."$key" = $value
            } else {
                $this.Add($key, $value)
            }
        }
    }
    [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
        $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
    }
    [void] LoadJson([string]$FilePath) {
        $this.LoadJson($FilePath, [System.Text.Encoding]::UTF8)
    }
    [void] LoadJson([string]$FilePath, [System.Text.Encoding]$Encoding) {
        [ValidateNotNullOrEmpty()][string]$FilePath = $FilePath
        [ValidateNotNullOrEmpty()][System.Text.Encoding]$Encoding = $Encoding
        $ob = ConvertFrom-Json -InputObject $([IO.File]::ReadAllText($FilePath, $Encoding))
        $ob | Get-Member -Type NoteProperty | Select-Object Name | ForEach-Object {
            $key = $_.Name; $val = $ob.$key; $this.Set($key, $val);
        }
    }
    [bool] Contains([string]$Name) {
        [ValidateNotNullOrEmpty()][string]$Name = $Name
        return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
    }
    [array] ToArray() {
        $array = @(); $props = $this | Get-Member -MemberType NoteProperty
        if ($null -eq $props) { return @() }
        $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
        return $array
    }
    [string] ToJson() {
        return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json)
    }
    [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
        [System.Collections.Specialized.OrderedDictionary]$dict = @{}; $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
        if ($Keys.Count -gt 0) {
            $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
        }
        return $dict
    }
    [string] ToString() {
        $r = $this.ToArray(); $s = ''
        $shortnr = [scriptblock]::Create({
                param([string]$str, [int]$MaxLength)
                while ($str.Length -gt $MaxLength) {
                    $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
                }
                return $str
            }
        )
        if ($r.Count -gt 1) {
            $b = $r[0]; $e = $r[-1]
            $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
            $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
            $s = "@($0 ... $1)"
        } elseif ($r.count -eq 1) {
            $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
            $s = "@($0)"
        } else {
            $s = '@()'
        }
        return $s
    }
}
class AzConfig : CfgList {
    [ValidateNotNullOrEmpty()][AzureResourceGroup]$AzureResourceGroup
    [ValidateNotNullOrEmpty()][string]$AzureServicePrincipalAppName
    [ValidateNotNullOrEmpty()][string]$AzureSubscriptionName
    [ValidateNotNullOrEmpty()][string]$AzureSubscriptionID
    [ValidateRange(1, 73000)][int]$CertExpirationDays
    [ValidateNotNullOrEmpty()][string]$AzureVaultName
    [ValidateNotNullOrEmpty()][string]$AzureTenantID
    [ValidateNotNullOrEmpty()][string]$CertName
    [ValidateNotNullOrEmpty()][string]$hsmName
    [ValidateNotNullOrEmpty()][string]$keyName
    [IO.FileInfo]$PrivateCertFile
    [IO.FileInfo]$PublicCertFile
    [bool]$KeepLocalPfxFiles
    [IO.FileInfo]$PfxFile
    [Email]$Email

    AzConfig() {
        $env = [System.IO.FileInfo]::New([IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env'))
        if ($env.Exists) { $this.Set($env.FullName) }; $this.SetCertPath(); if ($this.AzureLocation) { $this.AzureResourceGroup.Location = [AzureLocation]$this.AzureLocation }
    }
    hidden [void] Set([string]$key, $value) {
        [ValidateNotNullOrEmpty()][string]$key = $key
        [ValidateNotNullOrEmpty()][System.Object]$value = $value
        if ($key.ToLower() -eq 'certpath') {
            $this.SetCertPath($value)
        } elseif ($this.psObject.Properties.Name.Contains([string]$key)) {
            $this."$key" = $value
        } else {
            $this.Add($key, $value)
        }
    }
    hidden [void] Set([string]$EnvFile) {
        if (!(Test-Path -Path $EnvFile -PathType Leaf -ErrorAction Ignore)) {
            throw [System.IO.FileNotFoundException]::New()
        }
        $dict = [System.Collections.Specialized.OrderedDictionary]::New(); [IO.File]::ReadAllLines($EnvFile).ForEach({
                if (![string]::IsNullOrWhiteSpace($_) -and $_[0] -notin ('#', '//')) {
                        ($m, $d ) = switch -Wildcard ($_) {
                        "*:=*" { "Prefix", ($_ -split ":=", 2); Break }
                        "*=:*" { "Suffix", ($_ -split "=:", 2); Break }
                        "*=*" { "Assign", ($_ -split "=", 2); Break }
                        Default {
                            throw 'Unable to find Key value pair in line'
                        }
                    }
                    [void]$dict.Add($d[0].Trim(), $d[1].Trim())
                }
            }
        )
        $this.Set($dict);
    }
    hidden [void] SetCertPath() {
        $this.SetCertPath($(if ([bool](Get-Variable IsLinux -ValueOnly -ErrorAction Ignore) -or [bool](Get-Variable IsMacOS -ValueOnly -ErrorAction Ignore)) {
                    '/etc/ssl/private/'
                } elseif ([bool](Get-Variable IsWindows -ValueOnly -ErrorAction Ignore)) {
                    [IO.Path]::Combine($env:CommonProgramFiles, 'SSL', 'Private')
                } else {
                    $PSScriptRoot
                }
            )
        )
    }
    hidden [void] SetCertPath([string]$CertPath) {
        $this.PrivateCertFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).key.pem");
        $this.PublicCertFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).cert.pem")
        $this.PfxFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).pfx")
    }
}