function Initialize-EnvConfig {
    <#
    .SYNOPSIS
        A on-time-setup that prepares Credentials to use when securing environment variables on local machine.
    .DESCRIPTION
        Generates a secure hashed credential file and configuration for the EnvTools module.
        Has options to choose between DPAPI or AES encryption modes.
        DPAPI is more secure but requires to be run by the same user account on the same windows machine.
        AES is also secure but can be used when service account cannot be used to run in interactive mode.

    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Test-MyTestFunction -Verbose
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding()]
    param (

    )

    begin {
    }

    process {
    }

    end {
    }
}