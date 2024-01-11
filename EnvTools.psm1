#!/usr/bin/env pwsh

#region    Classes
#Requires -Version 7

using namespace System.IO
using namespace System.Drawing
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

enum Compression {
    Gzip
    Deflate
    ZLib
    # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}
#region    Shuffl3r
# .DESCRIPTION
#     Shuffles bytes, nonce, and other info into a jumbled mess that can be split using a password.
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible.
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
#     The donside is that: Input bytes.length has to be >= 16.
class Shuffl3r {
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
        return [Shuffl3r]::Combine($bytes, $Nonce, [AesGCM]::tostring($Passwod))
    }
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
        if ($bytes.Length -lt ($Nonce.Length + 1)) {
            throw [System.ArgumentOutOfRangeException]::new('$Bytes.length has to be >= $Nonce.Length')
        }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new($Nonce.Length);
        Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
        [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
        for ([int]$i = 0; $i -lt $Indices.Length; $i++) { $combined[$Indices[$i]] = $Nonce[$i] }
        $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
        foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
        return $combined
    }
    static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
        return [Shuffl3r]::Split($ShuffledBytes, [AesGCM]::tostring($Passwod), [int]$NonceLength);
    }
    static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
        if ($null -eq $ShuffledBytes) { throw [System.ArgumentNullException]::new('$ShuffledBytes') }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new([int]$NonceLength);
        Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
        $Nonce = [Byte[]]::new($NonceLength);
        [byte[]]$Bytes = @(); $i = 0; $rem = (0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices }
        foreach ($i in $rem) { $bytes += $ShuffledBytes[$i] };
        for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
        return ($bytes, $Nonce)
    }
    static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
        if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [System.ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
        if ([string]::IsNullOrWhiteSpace($randomString)) { throw [System.ArgumentNullException]::new('$randomString') }
        [Byte[]]$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$randomString))
        [int[]]$indices = [int[]]::new($Count)
        for ($i = 0; $i -lt $Count; $i++) {
            [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
            while ($indices -contains $nextIndex) {
                $nextIndex = ($nextIndex + 1) % $HighestIndex
            }
            $indices[$i] = $nextIndex
        }
        return $indices
    }
}
#endregion Shuffl3r

#region    AesGCM
# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $secmessage = [Aesgcm]::Encrypt("Yess this is a S3crEt!", (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#
#     # On recieving PC:
#     $orginalmsg = [AesGcm]::Decrypt($secmessage, (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo $orginalmsg # should be: Yess this is a S3crEt!
class AesGCM {
    static hidden [EncryptionScope] $Scope = [EncryptionScope]::User
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0);
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = $bytes;
            $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                    # Generate a random IV for each iteration:
                    [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
                    $tag = [byte[]]::new($TAG_SIZE);
                    $Encrypted = [byte[]]::new($_bytes.Length);
                    [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
                    $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
                ) Done"
            }
        } catch {
            if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                Write-Warning "Wrong password"
            }
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        if (![string]::IsNullOrWhiteSpace($Compression)) {
            $_bytes = [AesGCM]::ToCompressed($_bytes, $Compression);
        }
        return $_bytes
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [System.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0);
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ToDecompressed($bytes, $Compression) } else { $bytes }
            $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                    # Split the real encrypted bytes from nonce & tags then decrypt them:
                    ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                    ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                    $Decrypted = [byte[]]::new($b.Length);
                    $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                    $_bytes = $Decrypted;
                ) Done"
            }
        } catch {
            if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                Write-Warning "Wrong password"
            }
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        return $_bytes
    }
    static [byte[]] ToCompressed([byte[]]$Bytes) {
        return [AesGCM]::ToCompressed($Bytes, 'Gzip');
    }
    static [string] ToCompressed([string]$Plaintext) {
        return [convert]::ToBase64String([AesGCM]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
    }
    static [byte[]] ToCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $outstream = [System.IO.MemoryStream]::new()
        $Comstream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
        }
        [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes) {
        return [AesGCM]::ToDecompressed($Bytes, 'Gzip');
    }
    static [string] ToDecompressed([string]$Base64Text) {
        return [System.Text.Encoding]::UTF8.GetString([AesGCM]::ToDecompressed([convert]::FromBase64String($Base64Text)));
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $inpStream = [System.IO.MemoryStream]::new($Bytes)
        $ComStream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
        }
        $outStream = [System.IO.MemoryStream]::new();
        [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [string] ToString([System.Security.SecureString]$SecureString) {
        [string]$Pstr = [string]::Empty;
        [IntPtr]$zero = [IntPtr]::Zero;
        if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
            return [string]::Empty;
        }
        try {
            Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
            Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
        } finally {
            if ($zero -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
            }
        }
        return $Pstr;
    }
    static [SecureString] ToSecurestring([string]$String) {
        $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        if (![string]::IsNullOrEmpty($String)) {
            $Chars = $String.toCharArray()
            ForEach ($Char in $Chars) {
                $SecureString.AppendChar($Char)
            }
        }
        $SecureString.MakeReadOnly();
        return $SecureString
    }
    # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
    static [string] GetUniqueMachineId() {
        Write-Verbose "Get MachineId ..."
        $Id = [string]($Env:MachineId)
        $vp = (Get-Variable VerbosePreference).Value
        try {
            Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
            if ($HostOS -eq "Windows") {
                    if ([string]::IsNullOrWhiteSpace($Id)) {
                    $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                    Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineId))));
                }
                $Id = [string]($Env:MachineId)
            } elseif ($HostOS -eq "Linux") {
                # $Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
                # Lets use mac addresses
                $Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
                $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
            } elseif ($HostOS -eq "macOS") {
                $Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
                $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
            } else {
                throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
            }
        } catch {
            throw $_
        } finally {
            $sha256.Clear(); $sha256.Dispose()
            Set-Variable VerbosePreference -Value $vp
        }
        return $Id
    }
    static [byte[]] GetDerivedSalt([securestring]$password) {
        $rfc2898 = $null; $s4lt = $null; [byte[]]$s6lt = if ([AesGCM]::Scope.ToString() -eq "Machine") {
            [System.Text.Encoding]::UTF8.GetBytes([AesGcm]::GetUniqueMachineId())
        } else {
            [convert]::FromBase64String("qmkmopealodukpvdiexiianpnnutirid")
        }
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $password;
        Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $s6lt;
        Set-Variable -Name rfc2898 -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $s6lt));
        Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $($rfc2898.GetBytes(16));
        return $s4lt
    }
}
#endregion AesGCM

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
class EnvCfg : CfgList {
    [ValidateNotNullOrEmpty()][string]$AzureServicePrincipalAppName
    [ValidateRange(1, 73000)][int]$CertExpirationDays
    [IO.FileInfo]$PrivateCertFile
    [IO.FileInfo]$PublicCertFile
    [bool]$KeepLocalPfxFiles
    [IO.FileInfo]$PfxFile

    EnvCfg() {
        $env = [System.IO.FileInfo]::New([IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env'))
        if ($env.Exists) { $this.Set($env.FullName) }; $this.SetCertPath();
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

class EnvTools {
    [EnvCfg] $config
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert
    static hidden [string]$VarName_Suffix = '7fb2e877_6c2b_406a_af40_e1d915c62cdf'
    static hidden $X509CertHelper

    EnvTools() {}
    static [Array] Read([string]$EnvFile) {
        $content = Get-Content $EnvFile -ErrorAction Stop
        $res_Obj = [System.Collections.Generic.List[string[]]]::new()
        foreach ($line in $content) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                Write-Verbose "[GetdotEnv] Skipping empty line"
                continue
            }
            if ($line.StartsWith("#") -or $line.StartsWith("//")) {
                Write-Verbose "[GetdotEnv] Skipping comment: $line"
                continue
            }
            ($m, $d ) = switch -Wildcard ($line) {
                "*:=*" { "Prefix", ($line -split ":=", 2); Break }
                "*=:*" { "Suffix", ($line -split "=:", 2); Break }
                "*=*" { "Assign", ($line -split "=", 2); Break }
                Default {
                    throw 'Unable to find Key value pair in line'
                }
            }
            $res_Obj.Add(($d[0].Trim(), $d[1].Trim(), $m));
        }
        return $res_Obj
    }
    static [void] Update([string]$EnvFile, [string]$Key, [string]$Value) {
        [void]($d = [EnvTools]::Read($EnvFile) | Select-Object @{l = 'key'; e = { $_[0] } }, @{l = 'value'; e = { $_[1] } }, @{l = 'method'; e = { $_[2] } })
        $Entry = $d | Where-Object { $_.key -eq $Key }
        if ([string]::IsNullOrEmpty($Entry)) {
            throw [System.Exception]::new("key: $Key not found.")
        }
        $Entry.value = $Value; $ms = [PSObject]@{ Assign = '='; Prefix = ":="; Suffix = "=:" };
        Remove-Item $EnvFile -Force; New-Item $EnvFile -ItemType File | Out-Null;
        foreach ($e in $d) { "{0} {1} {2}" -f $e.key, $ms[$e.method], $e.value | Out-File $EnvFile -Append -Encoding utf8 }
    }

    static [void] Set([string]$EnvFile) {
        #return if no env file
        if (!(Test-Path $EnvFile)) {
            Write-Verbose "[setdotEnv] Could not find .env file"
            return
        }

        #read the local env file
        $content = [EnvTools]::Read($EnvFile)
        Write-Verbose "[setdotEnv] Parsed .env file: $EnvFile"
        foreach ($value in $content) {
            switch ($value[2]) {
                "Assign" {
                    [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                }
                "Prefix" {
                    $value[1] = "{0};{1}" -f $value[1], [System.Environment]::GetEnvironmentVariable($value[0])
                    [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                }
                "Suffix" {
                    $value[1] = "{1};{0}" -f $value[1], [System.Environment]::GetEnvironmentVariable($value[0])
                    [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                }
                Default {
                    throw [System.IO.InvalidDataException]::new()
                }
            }
        }
    }

    static [System.Object[]] RunAsync([scriptBlock]$command, [string]$StatusMsg) {
        # .SYNOPSIS
        #  Run Commands using Background Runspaces Instead of PSJobs For Better Performance
        $Comdresult = $null; [ValidateNotNullOrEmpty()][scriptBlock]$command = $command
        $PsInstance = [System.Management.Automation.PowerShell]::Create().AddScript($command)
        $job = $PsInstance.BeginInvoke();
        do {
            $ProgressPercent = if ([int]$job.TotalTime.TotalMilliseconds -ne 0) { [int]($job.RemainingTime.TotalMilliseconds / $job.TotalTime.TotalMilliseconds * 100) } else { 100 }
            Write-Progress -Activity "[EnvTools]" -Status "$StatusMsg" -PercentComplete $ProgressPercent
            Start-Sleep -Milliseconds 100
        } until ($job.IsCompleted)
        Write-Progress -Activity "[EnvTools]" -Status "command Complete." -PercentComplete 100
        if ($null -ne $PsInstance) {
            $Comdresult = $PsInstance.EndInvoke($job);
            $PsInstance.Dispose(); $PsInstance.Runspace.CloseAsync()
        }
        return $Comdresult
    }
    [guid] GetSessionId() {
        return [EnvTools]::GetSessionId($this)
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
        return [EnvTools]::VerifyGetSessionId([guid]$guid, $Source)
    }
    static [void] SetSessionCreds([guid]$sessionId) {
        [EnvTools]::SetSessionCreds([guid]$sessionId, $false)
    }
    static [void] SetSessionCreds([guid]$sessionId, [bool]$Force) {
        if (![string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable("$sessionId"))) { if (!$Force) { return } }
        [System.Environment]::SetEnvironmentVariable("$sessionId", $((Get-Credential -Message "Enter your Pfx Password" -Title "-----[[ PFX Password ]]-----" -UserName $env:username).GetNetworkCredential().SecurePassword | ConvertFrom-SecureString), [EnvironmentVariableTarget]::Process)
    }
    static hidden [void] refreshEnv() {
        $refrshrVarName = "refrshr_script_$([EnvTools]::VarName_Suffix)";
        if (!$(Get-Variable $refrshrVarName -ValueOnly -Scope script -ErrorAction Ignore)) {
            Set-Variable -Name $refrshrVarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/8b4ddc0302a9262cf7fc25e919227a2f).files.'Update_Session_Env.ps1'.content));
        }
        $refrshr_script = Get-Variable $refrshrVarName -ValueOnly -Scope script
        if ($refrshr_script) {
            Write-Host '[EnvTools] refreshing this Session Environment ...' -ForegroundColor Green
            . $refrshr_script; Update-SessionEnvironment
        } else {
            throw "Failed to fetch refresher script!"
        }
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateSelfSignedCertificate([EnvCfg]$EnvCfg, [string]$sessionId) {
        [EnvTools]::SetSessionCreds([guid]$sessionId)
        $X509VarName = "X509CertHelper_class_$([EnvTools]::VarName_Suffix)";
        if (!$(Get-Variable $X509VarName -ValueOnly -Scope script -ErrorAction Ignore)) {
            Write-Verbose "Fetching X509CertHelper class (One-time only)" -Verbose;
            Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/d8f277f1d830882c4927c144a99b70cd).files.'X509CertHelper.ps1'.content)));
        }
        $X509CertHelper_class = Get-Variable $X509VarName -ValueOnly -Scope script
        if ($X509CertHelper_class) { . $X509CertHelper_class; [EnvTools]::X509CertHelper = New-Object X509CertHelper }
        $Password = [System.Environment]::GetEnvironmentVariable($sessionId) | ConvertTo-SecureString
        return [EnvTools]::X509CertHelper::CreateSelfSignedCertificate("CN=$($EnvCfg.CertName)", $EnvCfg.PrivateCertFile, $Password, 2048, [System.DateTimeOffset]::Now.AddDays(-1).DateTime, [System.DateTimeOffset]::Now.AddDays($EnvCfg.CertExpirationDays).DateTime)
    }
    static hidden [void] Resolve_modules([string[]]$Names) {
        $varName = "resolver_script_$([EnvTools]::VarName_Suffix)";
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
#endregion Classes

# ----

$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $Module : $_"
        }
    }
}
# Dot source the files
foreach ($Import in ($Public, $Private)) {
    Try {
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
# Export Public Functions
$Public | ForEach-Object { Export-ModuleMember -Function $_.BaseName }
#Export-ModuleMember -Alias @('<Aliases>')