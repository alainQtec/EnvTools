if ($IsLinux) {
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
} elseif ($IsMacOS) {
    brew update && brew install azure-cli
} elseif ($IsWindows) {
    Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi
} else {
    throw "Unknowsn os"
}