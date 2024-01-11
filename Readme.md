# [EnvTools](EnvTools)

A module for loading and editing dotEnv environment variables. This module also includes cmdlets for extra safety measures.

It can securely read and write values in .env file using DPAPI or AES encryption modes to store the real values in a hashed credential file.

## Installation

```PowerShell
Install-Module EnvTools
```

## Features

Make dealing with environment variables easier.

- **Security**:

    Environment variables can be easily accessed by anyone who has access to the system. This can lead to security breaches if sensitive information is stored in environment variables. This module has cmdlets to create [encrypted Enviromment variables](https://github.com/alainQtec/EnvTools/wiki#enc)

- **Debugging**:

    Debugging issues can arise when environment variables are not set correctly or when they are not being passed correctly between different parts of the system.

- **Performance**:

    Cmdlets are benchmarked during tests to make sure they will not slow down the system.

## Usage

To use EnvTools, you need to import the module and then call its functions. For example:

```PowerShell
# Import the module
Import-Module EnvTools

# Read a value from .env file
Read-EnvValue -Name "API_KEY"

# Write a value to .env file
Write-EnvValue -Name "API_KEY" -Value "123456789"

# List all values in .env file
Get-EnvValues
```

## Issues

- **Compatibility issues**:
    Environment variables can behave differently on different platforms. For example, Windows and Unix-based systems have different ways of handling environment variables

## **License**

This module is licensed under the MIT [License](https://alainQtec.MIT-license.org).
