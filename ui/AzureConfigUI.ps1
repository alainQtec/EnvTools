#region    Common
# Common Functions, Variables and Assemblies
[Void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[Void][System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\Assembly\MaterialDesignThemes.Wpf.dll")
[Void][System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\Assembly\MaterialDesignColors.dll")

[regex]$Script:RegEx_Numbers = '^[0-9]*$'
[regex]$Script:RegEx_AlphaNumeric = '^[a-zA-Z0-9]*$'
[regex]$Script:RegEx_Letters = '^[a-zA-Z]*$'
[regex]$Script:RegEx_LettersSpace = '^[\sa-zA-Z]*$'
[regex]$Script:RegEx_AlphaNumericSpaceUnderscore = '^[\s_a-zA-Z0-9]*$'
[regex]$Script:RegEx_NoteChars = '^[\s_\"\.\-,a-zA-Z0-9]*$'
[regex]$Script:RegEx_EmailChars = '^[\@\.\-a-zA-Z0-9]*$'
[regex]$Script:RegEx_EmailPattern = '^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$'
[regex]$Script:RegEx_NumbersDash = '^[\-0-9]*$'

enum ThemeMode {
    Dark
    Light
}


class MaterialUI {
    static $MessageQueue
    static [string] $OpenFilePath
    static $NavigationRailTab
    MaterialUI() {}

    static [System.Object] CreateWindow([IO.FileInfo]$XamlFile) {
        return [MaterialUI]::CreateWindow($XamlFile, $true)
    }
    static [System.Object] CreateWindow([IO.FileInfo]$XamlFile, [bool]$NoSnackbar) {
        [xml]$Xaml = (Get-Content -Path $XamlFile.FullName)
        $Reader = New-Object System.Xml.XmlNodeReader $Xaml
        $Window = (New-Object Windows.Markup.XamlReader)::Load($Reader)
        $Xaml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Window.FindName($_.Name) -Scope Script }
        # Objects that have to be declared before the window launches (will run in the same dispatcher thread as the window)
        if (!$NoSnackbar) {
            [MaterialUI]::MessageQueue = New-Object MaterialDesignThemes.Wpf.SnackbarMessageQueue
            [MaterialUI]::MessageQueue.DiscardDuplicates = $true
        }
        return $Window
    }
    # Generates a Snackbar message with an optional button.
    static [void]  CreateSnackbar($Snackbar, $Text, [bool]$ButtonCaption) {
        if ($ButtonCaption) {
            [MaterialUI]::MessageQueue.Enqueue($Text, $ButtonCaption, { $null }, $null, $false, $false, [TimeSpan]::FromHours( 9999 ))
        } else {
            [MaterialUI]::MessageQueue.Enqueue($Text, $null, $null, $null, $false, $false, $null)
        }
        $Snackbar.MessageQueue = [MaterialUI]::MessageQueue
    }
    static [void] SetNavigationRailTab($NavigationRail, [string]$TabName) {
        [MaterialUI]::NavigationRail = $NavigationRail
        [MaterialUI]::NavigationRail.SelectedIndex = [array]::IndexOf((($NavigationRail.Items | Select-Object -ExpandProperty name).toupper()), $TabName.ToUpper())
    }
    [System.Object] GetSelectedTabControl() {
        # Returns the name of the current selected tab of a TabControl.
        return [MaterialUI]::NavigationRail.Items | Where-Object { $_.IsSelected -eq "True" } | Select-Object -ExpandProperty name
    }
    [string] GetSaveFilePath([string] $InitialDirectory, [string] $Filter) {
        # Opens a save-file windows dialog and returns the name and path of the file to be saved.
        $SaveFileDialog = New-Object Microsoft.Win32.SaveFileDialog
        $SaveFileDialog.initialDirectory = $InitialDirectory
        $SaveFileDialog.filter = $Filter
        $SaveFileDialog.CreatePrompt = $False;
        $SaveFileDialog.OverwritePrompt = $True;
        $SaveFileDialog.ShowDialog() | Out-Null
        return $SaveFileDialog.filename
    }
    static [void] SetCurrentCulture () {
        [MaterialUI]::SetCurrentCulture(2057)
        #2057 = English (UK)   ,  1033 = English (US)
    }
    static [void] SetCurrentCulture ([int]$LCID) {
        #Sets the PS Session's culture. All Time and Date UI controls will be effected by that. (DatePicker for example).
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo($LCID)
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
    }
    static [void] OpenFileDialog([string]$InitialDirectory, [string]$Filter) {
        $FileDialog = New-Object Microsoft.Win32.OpenFileDialog
        $FileDialog.initialDirectory = $InitialDirectory
        $FileDialog.filter = $Filter
        # Examples of other common filters: "Word Documents|*.doc|Excel Worksheets|*.xls|PowerPoint Presentations|*.ppt |Office Files|*.doc;*.xls;*.ppt |All Files|*.*"
        $FileDialog.ShowDialog() | Out-Null
        [MaterialUI]::OpenFilePath = $FileDialog.filename
    }
    [string] GetOpenFilePath() {
        if ([string]::IsNullOrWhiteSpace([MaterialUI]::OpenFilePath)) {
            [MaterialUI]::OpenFileDialog()
        }
        return [MaterialUI]::OpenFilePath
    }
    static [System.Object] GetSystemTheme() {
        # Will return "Dark" or "Light" based on the current apps theme mode set in windows OS
        return (New-Object MaterialDesignThemes.Wpf.Theme)::GetSystemTheme()
    }
    static [System.Object] GetThemeMode($Window) {
        # Returns the given app window theme mode ("Dark" or "Light")
        return ([scriptblock]::Create('[MaterialDesignThemes.Wpf.ThemeExtensions]::GetBaseTheme($([MaterialDesignThemes.Wpf.ResourceDictionaryExtensions]::GetTheme($Window.Resources)))').Invoke())
    }
}

function Set_ValidationError {
    # (1)Marks/Clears an element's validity, (2)Will return an element vaildity state, (3)Will set an error message for invalid element.
    param (
        $UIObject,
        $ErrorText,
        [switch]$CheckHasError,
        [switch]$ClearInvalid
    )
    #https://coderedirect.com/questions/546371/setting-validation-error-template-from-code-in-wpf
    # !!! you must put  Text="{Binding txt}" in the textbox xaml code.
    $ClassProperty =
    switch ($UIObject.GetType().name) {
        "TextBox" { [System.Windows.Controls.TextBox]::TextProperty }
        "ComboBox" { [System.Windows.Controls.ComboBox]::SelectedItemProperty }
        "TimePicker" { [MaterialDesignThemes.Wpf.TimePicker]::TextProperty }
        "DatePicker" { [System.Windows.Controls.DatePicker]::SelectedDateProperty }
        # For RatingBar - you must put this in the xaml part --> Value="{Binding Path=BlaBla, Mode=TwoWay}" . Also don't use the Validation.ErrorTemplate attribute. It will show red border, no text.
        "RatingBar" { [MaterialDesignThemes.Wpf.RatingBar]::ValueProperty }
        #"Calendar"    {[System.Windows.Controls.Calendar]::SelectedDateProperty}   Wasn't tested yet
        #"ListBox"     {[System.Windows.Controls.ListBox]::SelectedItemProperty}    Wasn't tested yet
        #"RadioButton" {[System.Windows.Controls.RadioButton]::IsCheckedProperty}   Wasn't tested yet
        # "PasswordBox" {[system.Windows.Controls.PasswordBox]::Password}           Wasn't tested yet
        #"RichTextBox" {[System.Windows.Controls.RichTextBox]::Document}            Wasn't tested yet
    }
    [System.Windows.Data.BindingExpression]$bindingExpression = [System.Windows.Data.BindingOperations]::GetBindingExpression( $UIObject, $ClassProperty)
    [System.Windows.Data.BindingExpressionBase]$bindingExpressionBase = [System.Windows.Data.BindingOperations]::GetBindingExpressionBase($UIObject, $ClassProperty);
    [System.Windows.Controls.ValidationError]$validationError = [System.Windows.Controls.ValidationError]::new([System.Windows.Controls.ExceptionValidationRule]::New(), $bindingExpression)

    <# This option will put the error message on either Absolute,AbsolutPoint,Bottom,Center,Custom,Left,Right,Top,MousePoint,Mouse,Relative,RelativePoint. Default is bottom.
    [MaterialDesignThemes.Wpf.ValidationAssist]::SetUsePopup($UIObject,$true)
    [MaterialDesignThemes.Wpf.ValidationAssist]::SetPopupPlacement($UIObject,[System.Windows.Controls.Primitives.PlacementMode]::Top)
    #>
    if ($CheckHasError) {
        return [System.Windows.Controls.Validation]::GetHasError($UIObject)
    } else {
        if ($ClearInvalid) {
            [System.Windows.Controls.Validation]::ClearInvalid($bindingExpressionBase)
        } else {
            $validationError.ErrorContent = $ErrorText
            [System.Windows.Controls.Validation]::MarkInvalid($bindingExpressionBase, $validationError)
        }
    }
}

function Confirm-RequiredField {
    # Will call Set_ValidationError to Mark/Clear an element if its text is $null or not respectively.
    param (
        $UI_Object = $this,
        $ErrorText = "This field is mandatory"
    )
    if (!$UI_Object.Text) {
        Set_ValidationError -UIObject $UI_Object -ErrorText $ErrorText
    } else {
        Set_ValidationError -UIObject $UI_Object -ClearInvalid
    }
}

function Confirm-TextPatternField {
    # Will call Set_ValidationError to Mark/Clear an element if its text does not match or matches a regular expression respectively.
    param (
        $UI_Object = $this,
        $ErrorText = "Invalid Value",
        [regex[]]$Regex
    )
    $IsValid = $false
    foreach ($Pattern in $Regex) {
        if ($UI_Object.Text -match $Pattern) {
            $IsValid = $true
            break
        }
    }
    if ($IsValid) {
        Set_ValidationError -UIObject $UI_Object -ClearInvalid
    } else {
        Set_ValidationError -UIObject $UI_Object -ErrorText $ErrorText
    }
}

function  Confirm-TextInput {
    # Blocks character from entered into an input element, based on a regular expression match
    param(
        $UI_Object = $this,
        $RegexPattern,
        [switch]$ToUpper
    )
    $SelectionStart = $UI_Object.SelectionStart
    $TextLength = ($UI_Object.text).length
    $TmpArray = $UI_Object.text.ToCharArray()
    $Output = $TmpArray | ForEach-Object { $_ | Where-Object { $_ -match $RegexPattern } }
    $UI_Object.text = if ($ToUpper) { (-join $Output).ToUpper() } else { (-join $Output) }
    if ( ($UI_Object.text).length -lt $TextLength ) {
        $UI_Object.SelectionStart = $SelectionStart - 1
    } else { $UI_Object.SelectionStart = $SelectionStart }
}

#endregion Common

#region    Theme

[System.Collections.ArrayList]$ThemePrimaryColors = [System.Enum]::GetNames([MaterialDesignColors.PrimaryColor])
$ThemePrimaryColors.Sort()
[System.Collections.ArrayList]$ThemeSecondaryColors = [System.Enum]::GetNames([MaterialDesignColors.SecondaryColor])
$ThemeSecondaryColors.Sort()
function  SetTheme {
    # Sets the window theme colors and mode
    param(
        $Window,
        $PrimaryColor,
        $SecondaryColor,
        [Parameter()]
        [ValidateSet('Dark', 'Light')]
        $ThemeMode
    )
    $Theme = [MaterialDesignThemes.Wpf.ResourceDictionaryExtensions]::GetTheme($Window.Resources)
    if ($PrimaryColor) {
        $PrimaryColorObj = [MaterialDesignColors.SwatchHelper]::Lookup[$PrimaryColor]
        [void][MaterialDesignThemes.Wpf.ThemeExtensions]::SetPrimaryColor($Theme, $PrimaryColorObj)
    }
    if ($SecondaryColor) {
        $SecondaryColorObj = [MaterialDesignColors.SwatchHelper]::Lookup[$SecondaryColor]
        [void][MaterialDesignThemes.Wpf.ThemeExtensions]::SetSecondaryColor($Theme, $SecondaryColorObj)
    }
    if ($ThemeMode) {
        [void][MaterialDesignThemes.Wpf.ThemeExtensions]::SetBaseTheme($Theme, [MaterialDesignThemes.Wpf.Theme]::$ThemeMode)
    }
    [void][MaterialDesignThemes.Wpf.ResourceDictionaryExtensions]::SetTheme($Window.Resources, $Theme)
}


#endregion Theme

$Window = [MaterialUI]::CreateWindow($(Get-Item -Path "$PSScriptRoot\AzureConfigUI.xaml"), $false)
$TextBox_Output.AppendText("Main Runspace ID: $(([System.Management.Automation.Runspaces.Runspace]::DefaultRunSpace).id)`n")
class ObjectOutPut {
    <# Define the class. Try constructors, properties, or methods. #>
}
$Btn_StartConfigJobs.Add_Click({
        $HsmConfigCard.IsEnabled = $false
        $SpinnerOverlayLayer.Visibility = "Visible"

        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    HsmConfigCard       = $HsmConfigCard
                }
            )
        )
        $Runspace = [runspacefactory]::CreateRunspace()
        $Runspace.ThreadOptions = "ReuseThread"
        $Runspace.ApartmentState = "STA"
        $Runspace.Open()
        $Runspace.SessionStateProxy.SetVariable("SyncHash", $SyncHash)
        $Worker = [PowerShell]::Create().AddScript({
                $RunspaceID = ([System.Management.Automation.Runspaces.Runspace]::DefaultRunSpace).id
                $SyncHash.Window.Dispatcher.Invoke([action] { $SyncHash.TextBox_Output.AppendText("New Runspace ID: $RunspaceID`n") }, "Normal")
                $Results = [System.Text.StringBuilder]::new()
                # just an example:
                foreach ($number in 1..10000000) {
                    if (($number % 2560583 ) -eq 0) {
                        [void]$Results.AppendLine($number)
                    }
                }
                if ($Results) {
                    $SyncHash.Window.Dispatcher.Invoke([action] { $SyncHash.TextBox_Output.AppendText($Results.ToString()) }, "Normal")
                }
                $SyncHash.Window.Dispatcher.Invoke([action] { $SyncHash.SpinnerOverlayLayer.Visibility = "Collapsed" }, "Normal")
                $SyncHash.Window.Dispatcher.Invoke([action] { $SyncHash.HsmConfigCard.IsEnabled = $true }, "Normal")
            }
        )
        $Worker.Runspace = $Runspace

        Register-ObjectEvent -InputObject $Worker -EventName InvocationStateChanged -Action {
            param([System.Management.Automation.PowerShell] $ps)
            $state = $EventArgs.InvocationStateInfo.State
            if ($state -in 'Completed', 'Failed') {
                $ps.EndInvoke($Worker)
                $ps.Runspace.Dispose()
                $ps.Dispose()
                [GC]::Collect()
            }
        } | Out-Null
        Register-ObjectEvent -InputObject $Runspace -EventName AvailabilityChanged -Action {
            if ($($EventArgs.RunspaceAvailability) -eq 'Available') {
                $Runspace.Dispose()
                [GC]::Collect()
            }
        } | Out-Null

        $Worker.BeginInvoke()
    }
)

# region    popup_cards
$Btn_Popup_AZ_Inputs.Add_Click({
        $HsmConfigCard.IsEnabled = $true
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $HsmConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $HsmConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)
$Btn_Popup_AZ_user_Inputs.Add_Click({
        $azUserConfigCard.IsEnabled = $true
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $azUserConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $azUserConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)
$Btn_Popup_git_repo_config.Add_Click({
        $gitConfigCard.IsEnabled = $true
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $gitConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $gitConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)
$Btn_Popup_certificates_config.Add_Click({
        $certConfigCard.IsEnabled = $true
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $certConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $azUserConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)
# endregion popup_cards

# region    close_buttons
$Btn_HsmConfigCard_Close.Add_Click({
        $HsmConfigCard.IsEnabled = $false
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $HsmConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Hidden"
        $HsmConfigCard.Visibility = "Hidden"
        $MainWindow.Height = 460
        $MainWindow.width = 450
    }
)
$Btn_azUserConfigCard_Close.Add_Click({
        $azUserConfigCard.IsEnabled = $false
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $azUserConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Hidden"
        $azUserConfigCard.Visibility = "Hidden"
        $MainWindow.Height = 460
        $MainWindow.width = 450
    }
)
$Btn_certConfigCard_Close.Add_Click({
        $certConfigCard.IsEnabled = $false
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $certConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Hidden"
        $certConfigCard.Visibility = "Hidden"
        $MainWindow.Height = 460
        $MainWindow.width = 450
    }
)
$Btn_gitConfigCard_Close.Add_Click({
        $gitConfigCard.IsEnabled = $false
        Set-Variable -Name SyncHash -Scope Global -Value $([hashtable]::Synchronized(@{
                    Window              = $window
                    SpinnerOverlayLayer = $SpinnerOverlayLayer
                    TextBox_Output      = $TextBox_Output
                    ActiveConfigCard    = $gitConfigCard
                }
            )
        )
        $DarkBgOverlayLayer.Visibility = "Hidden"
        $gitConfigCard.Visibility = "Hidden"
        $MainWindow.Height = 460
        $MainWindow.width = 450
    }
)
# endregion close_buttons
$Window.ShowDialog() | Out-Null

# user
# - AzureSubscriptionID          = # tooltip should be GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
# - AzureSubscriptionName        = # tooltip should be Create your Az Subscription : 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/SubscriptionCreateBlade' # AZURE SUBSCRIPTION NAME FORMAT: <Company>-<Department>-sub-<Environment>
# - AzureResourceGroup           = # Name Your ResGroup
# - AzureTenantID                = # tooltip should be : GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
# - Email                        = # user's azure Email


# hsm:
# - AzureServicePrincipalAppName = # default is "Envtools"
# - AzureVaultName               = # Name the vault to use
# - CertName                     = # tooltip should be : example "Envtools-cert"
# - hsmName                      = # example "Envtools-Hsm"
# - keyName                      = # example "Envtools-Key"


<#
Can you edit the xaml form to have these inputs above the startConfigJobs Button?

- AzureServicePrincipalAppName = # default is "Envtools"
- AzureSubscriptionName        = # tooltip should be Create your Az Subscription : 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/SubscriptionCreateBlade' # AZURE SUBSCRIPTION NAME FORMAT: <Company>-<Department>-sub-<Environment>
- AzureSubscriptionID          = # tooltip should be GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
- AzureResourceGroup           = # Name Your ResGroup
- AzureVaultName               = # Name the vault to use
- AzureTenantID                = # tooltip should be : GET One: 'https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id'
- CertName                     = # tooltip should be : example "Envtools-cert"
- hsmName                      = # example "Envtools-Hsm"
- keyName                      = # example "Envtools-Key"
- Email                        = # user's azure Email
#>