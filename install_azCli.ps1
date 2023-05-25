if ($IsLinux) {
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
} elseif ($IsMacOS) {
    <# Action when this condition is true #>
} elseif ($IsWindows) {
    <# Action when this condition is true #>
} else {
    throw "Unknowsn os"
}