#!/usr/bin/env pwsh
#region    Classes
class IDVault {
    IDVault() {}
    # $c = [IO.File]::ReadAllText((Get-Item .\creds.yml).FullName) | ConvertFrom-Yaml
}
enum AzureLocation {
    AustraliaCentral
    AustraliaCentral2
    AustraliaEast
    AustraliaSoutheast
    BrazilSouth
    BrazilSoutheast
    CanadaCentral
    CanadaEast
    CentralIndia
    CentralUS
    ChinaEast
    ChinaEast2
    ChinaNorth
    ChinaNorth2
    EastAsia
    EastUS
    EastUS2
    FranceCentral
    FranceSouth
    GermanyCentral
    GermanyNorth
    GermanyNorthEast
    GermanyWestCentral
    JapanEast
    JapanWest
    KoreaCentral
    KoreaSouth
    NorthCentralUS
    NorthEurope
    NorwayEast
    NorwayWest
    QatarCentral
    SouthAfricaNorth
    SouthAfricaWest
    SouthCentralUS
    SoutheastAsia
    SouthIndia
    SwedenCentral
    SwitzerlandNorth
    SwitzerlandWest
    UAECentral
    UAENorth
    UKSouth
    UKWest
    USDoDCentral
    USDoDEast
    USGovArizona
    USGovIowa
    USGovTexas
    USGovVirginia
    WestCentralUS
    WestEurope
    WestIndia
    WestUS
    WestUS2
    WestUS3
    # See Azure [documentation](https://learn.microsoft.com/en-us/dotnet/api/azure.core.azurelocation) for the exhaustive list
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
#  Your_Key_Vault                  = 'https://azure.microsoft.com/en-us/services/key-vault/'
class HsmVault {
    [AzConfig] $config
    static [PSCredential] $creds
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    static hidden [bool]$IsSetup = [bool][int]$env:Is_HsmVault_Setup

    HsmVault() {
        $this.config = [AzConfig]::New()
        $this.Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $this.Cert.Subject = "/C=LV/ST=Rwanda/L=1/O=$($this.config.CertName)/OU=IT"
        $this.Authenticate()
    }
    HsmVault([string]$AzureVaultName, [AzureResourceGroup]$AzureResourceGroup, [string]$AzureSubscriptionID) {
        $this.config = [AzConfig]::New()
        $this.Config.AzureVaultName = $AzureVaultName
        $this.Config.AzureResourceGroup = $AzureResourceGroup
        $this.Config.AzureSubscriptionID = $AzureSubscriptionID
        $this.Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $this.Cert.Subject = "/C=LV/ST=Rwanda/L=1/O=$($this.config.CertName)/OU=IT"
        $this.Authenticate()
    }
    [void] Setup() {
        # https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-powershell
        $null = [HsmVault]::RunAsync({ $AzIsnotInstalled = $null -eq (Get-Module -ListAvailable az)[0];
                if ($AzIsnotInstalled) { Install-Module -Name Az -AllowClobber -Scope AllUsers };
                Enable-AzureRmAlias
            }, 'Enable Aliases from the previous Azure RM'
        )
        $null = [HsmVault]::RunAsync({ Connect-AzAccount }, 'Connect-AzAccount, Waiting the Browser ...')
        $null = [HsmVault]::RunAsync({ Set-AzContext -SubscriptionName $this.config.AzureSubscriptionName; New-AzResourceGroup -Name $this.config.AzureResourceGroup.Name -Location $this.config.AzureResourceGroup.Location.ToString() }, 'Set resource Group')
        $principalId = [HsmVault]::RunAsync({ (Get-AzADUser -UserPrincipalName $this.config.Email.Address).Id }, 'Getting your principal ID ...')
        Write-Host "[HsmVault] Creating a managed HSM .." -ForegroundColor Green

        $null = [HsmVault]::RunAsync({ New-AzKeyVaultManagedHsm -AzureResourceGroup $this.config.AzureResourceGroup.Name -Name $this.config.hsmName -Location $this.config.location -Sku Standard_B1 -Administrators $principalId }, 'Creating a managed HSM ...')
        Write-Host "[HsmVault] Generate a certificate locally which will be used to Authenticate" -ForegroundColor Green
        $_crt = [HsmVault]::CreateCert($this.config); $keyValue = [System.Convert]::ToBase64String($_crt.GetRawCertData())

        $sp = [HsmVault]::RunAsync({
                New-AzADServicePrincipal -DisplayName $this.config.AzureServicePrincipalAppName -CertValue $keyValue -EndDate $_crt.NotAfter -StartDate $_crt.NotBefore
                (Get-AzSubscription -SubscriptionName $this.config.AzureSubscriptionName).TenantId
                # How do I know that the service principal has succesfully propagated in Azure???
                # It seems; this is a problem!
            },
            'Generate a service principal (Application) that we will use to Authenticate with'
        )
        $null = $this.config.Set('ApplicationId', $sp.ApplicationId.Guid)
        $null = [HsmVault]::RunAsync({ New-AzRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $sp.ApplicationId -ResourceGroupName $this.config.AzureResourceGroup.Name -ResourceType "Microsoft.KeyVault/vaults" -ResourceName $this.config.hsmName }, 'Assign the appropriate role to the service principal ...')
        $null = [HsmVault]::RunAsync({ Set-AzKeyVaultAccessPolicy -VaultName $this.config.hsmName -ObjectId $sp.id -PermissionsToSecrets Get, Set }, 'Set the appropriate access to the secrets for the application ...')

        Set-Item -Path ([IO.Path]::Combine('Env:', 'Is_HsmVault_Setup')) -Value 1 -Force
        Write-Host ''
        Write-Host -ForegroundColor Blue "Tenant ID: $($this.config.AzureTenantID)"
        Write-Host -ForegroundColor Blue "Application ID: $($this.config.ApplicationId)"
        Write-Host -ForegroundColor Blue "Azure Key Vault Name: $($this.config.hsmName)"
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
        $job = $PsInstance.BeginInvoke(); while (!$job.IsCompleted) {
            $ProgressPercent = if ([int]$job.TotalTime.TotalMilliseconds -ne 0) { [int]($job.RemainingTime.TotalMilliseconds / $job.TotalTime.TotalMilliseconds * 100) } else { 100 }
            Write-Progress -Activity "[HsmVault]" -Status "$StatusMsg" -PercentComplete $ProgressPercent
            Start-Sleep -Milliseconds 100
        }
        Write-Progress -Activity "[HsmVault]" -Status "command Complete." -PercentComplete 100
        $Comdresult = $PsInstance.EndInvoke($job)
        $PsInstance.Dispose();
        return $Comdresult
    }
    hidden [void] Authenticate() {
        if (![HsmVault]::IsSetup) {
            Write-Host '[HsmVault] Setting up an Azure Key Vault (One time only) ...' -ForegroundColor Green
            $this.Setup()
        }; $null = [HsmVault]::RunAsync({ Login-AzAccount }, 'AzAccount login')
        Write-Host "[HsmVault] Azure account Authentication complete." -ForegroundColor Green
    }
    hidden [void] Createkey([string]$keyName) {
        Write-Host "[HsmVault] Creating HSM key ..." -ForegroundColor Green
        Add-AzKeyVaultKey -HsmName $this.config.hsmName -Name $keyName -Destination HSM
    }
    static hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateCert([AzConfig]$AzConfig) {
        if (!$AzConfig.PfxFile.Exists) {
            # Generate new certificate and convert it to pfx format
            $openssl = [HsmVault]::GetOpenssl().FullName
            &$openssl req -newkey rsa:2048 -new -nodes -x509 -days $AzConfig.CertExpirationDays -keyout $AzConfig.PrivateCertFile.FullName -out $AzConfig.PublicCertFile.FullName -subj "/C=LV/ST=Rwanda/L=1/O=$($AzConfig.CertName)/OU=IT"
            [HsmVault]::creds = Get-Credential -Message "Password protect your Pfx file" -Title "-----[| Pfx Password |]-----" -UserName $env:username
            &$openssl pkcs12 -in $AzConfig.PublicCertFile.FullName -inkey $AzConfig.PrivateCertFile.FullName -export -out $AzConfig.PfxFile.FullName -passout pass:$([HsmVault]::creds.GetNetworkCredential().Password)
        }
        return [HsmVault]::CreateCert($AzConfig.CertName, $AzConfig.PfxFile.FullName, [HsmVault]::creds.GetNetworkCredential().SecurePassword)
    }
    static hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateCert([string]$CertName, [string]$PfxPath, [securestring]$Password) {
        # Creates and Stores X509Cert2 in certificate store
        $X509Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable);
        $CertStore = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser);
        $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);
        $X509Cert2.FriendlyName = $CertName;
        $CertStore.Add($X509Cert2)
        $CertStore.Close()
        return $X509Cert2
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
        Connect-AzAccount -ServicePrincipal -CertificateThumbprint $this.GetThumbPrint() -ApplicationId $ApplicationId -TenantId $this.Config.AzureTenantID
        $Secret = (Get-AzKeyVaultSecret -VaultName $this.config.AzureVaultName -Name "ExamplePassword").SecretValueText
        return $Secret
    }
    [string] GetThumbPrint() { return $this.GetThumbPrint($this.Cert.Subject) }
    [string] GetThumbPrint([string]$certSubject) {
        $CertStore = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); $Thumbprints = $CertStore.Certificates.Where({ $_.Subject -eq $this.Cert.Subject -and $_.FriendlyName -eq ($this.config.AzureTenantID + '-cert') }).Thumbprint
        if ($Thumbprints.count -gt 1) { Write-Warning 'Ambiguous certs' }
        $this.Cert.Thumbprint = $Thumbprints[0];
        $CertStore.Close()
        return $this.Cert.Thumbprint
    }
    static [IO.FileInfo] GetOpenssl () {
        # Return the path to openssl executable file + Will install it if not found.
        $res = [IO.FileInfo](Get-Command -Name OpenSSL -Type Application -ErrorAction Ignore).Source
        if (!$res -or !$res.Exists) {
            if (!(Get-Command -Name Install-OpenSSL -Type ExternalScript -ErrorAction Ignore)) { Install-Script -Name Install-OpenSSL -Repository PSGallery -Scope CurrentUser }
            Install-OpenSSL
        }
        return $res
    }
    [Byte[]] RetrieveKey([string]$keyName) {
        return (Get-AzKeyVaultKey -HsmName $this.config.hsmName -Name $keyName)
    }
    static [securestring] ConvertToSecureString([string]$plainText) {
        $private:Sec = $null; Set-Variable -Name Sec -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        $plainText.toCharArray().forEach({ [void]$Sec.AppendChar($_) }); $Sec.MakeReadOnly()
        return $Sec
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
    [string] $Algorithm
    [string] $Operation
    [string] $Result
    [string] $Message

    HsmKeyOperationResult([string]$key, [string]$algorithm, [string]$operation, [string]$result, [string]$message) {
        $this.Key = [HsmVault]::ConvertToSecureString($key)
        $this.Algorithm = $algorithm
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
        $this.Location = [AzureLocation]::UKWest
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
    [Ordered] ToOrdered() {
        $dict = [Ordered]@{}; $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
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
    [AzureResourceGroup]$AzureResourceGroup
    [string]$AzureServicePrincipalAppName
    [string]$AzureSubscriptionName
    [IO.FileInfo]$PrivateCertFile
    [IO.FileInfo]$PublicCertFile
    [string]$AzureSubscriptionID
    [int]$CertExpirationDays
    [bool]$KeepLocalPfxFiles
    [string]$AzureVaultName
    [string]$AzureTenantID
    [IO.FileInfo]$PfxFile
    [string]$CertPath
    [string]$CertName
    [string]$hsmName
    [string]$keyName
    [Email]$Email

    AzConfig() {
        $this.CertPath = $(if ([bool](Get-Variable IsWindows -ValueOnly -ErrorAction Ignore)) {
                [IO.Path]::Combine($env:CommonProgramFiles, 'SSL', 'Private')
            } else { '/etc/ssl/private/' }
        )
        if ($this.AzureLocation) { $this.AzureResourceGroup.Location = [AzureLocation]$this.AzureLocation }
        $env = [System.IO.FileInfo]::New([IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env'))
        if ($env.Exists) { $this.Set($env.FullName) }; ('PublicCertFile', 'PrivateCertFile', 'PfxFile').ForEach({ if (!$this."$_") { $this."$_" = [IO.FileInfo]::new([char]8) } })
    }
    hidden [void] Set([string]$key, $value) {
        [ValidateNotNullOrEmpty()][string]$key = $key
        [ValidateNotNullOrEmpty()][System.Object]$value = $value
        if ($this.PsObject.Properties.$key -and $key -eq 'CertPath') {
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
        $dict = [ordered]::New(); [IO.File]::ReadAllLines($EnvFile).ForEach({
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
    hidden [void] SetCertPath([string]$Path) {
        $this.CertPath = $Path
        $this.PrivateCertFile = [IO.FileInfo][IO.Path]::Combine($this.CertPath, $this.CertName + 'key.pem');
        $this.PublicCertFile = [IO.FileInfo][IO.Path]::Combine($this.CertPath, $this.CertName + 'cert.pem')
        $this.PfxFile = [IO.FileInfo][IO.Path]::Combine($this.CertPath, $this.CertName + '.pfx')
    }
}

