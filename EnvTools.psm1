#!/usr/bin/env pwsh
#region    Classes
class EnvTools {
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
}
#endregion Classes
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
foreach ($Import in ($Public + $Private)) {
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