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

function New-Window {
    # Sets a new WPF window from a xaml file and declares all named elements as variables. It will also optionally set a Snackbar Queue.
    param (
        $XamlFile,
        [Switch]$NoSnackbar
    )

    try {
        [xml]$Xaml = (Get-Content $XamlFile)
        $Reader = New-Object System.Xml.XmlNodeReader $Xaml
        $Window = [Windows.Markup.XamlReader]::Load($Reader)

        $Xaml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Window.FindName($_.Name) -Scope Script }
        # Objects that have to be declared before the window launches (will run in the same dispatcher thread as the window)
        if (!$NoSnackbar) {
            $Script:MessageQueue = [MaterialDesignThemes.Wpf.SnackbarMessageQueue]::new()
            $Script:MessageQueue.DiscardDuplicates = $true
        }

        return $Window
    } catch {
        Write-Error "Error building Xaml data or loading window data.`n$_"
        exit
    }
}

function New-Snackbar {
    # Generates a Snackbar message with an optional button.
    param (
        $Snackbar,
        $Text,
        $ButtonCaption
    )
    try {
        if ($ButtonCaption) {
            $MessageQueue.Enqueue($Text, $ButtonCaption, { $null }, $null, $false, $false, [TimeSpan]::FromHours( 9999 ))
        } else {
            $MessageQueue.Enqueue($Text, $null, $null, $null, $false, $false, $null)
        }
        $Snackbar.MessageQueue = $MessageQueue
    } catch {
        Write-Error "No MessageQueue was declared in the window. Make sure -NoSnackbar switch wasn't used in New-Window`n$_"
    }
}

function Set-NavigationRailTab {
    # Accepts a TabControl and tab name parameters and sets the tab name as selected tab.
    param (
        $NavigationRail,
        $TabName
    )
    $NavigationRail.SelectedIndex = [array]::IndexOf((($NavigationRail.Items | Select-Object -ExpandProperty name).toupper()), $TabName.ToUpper())
}

function Get-NavigationRailSelectedTabName {
    # Returns the name of the current selected tab of a TabControl.
    param (
        $NavigationRail
    )
    return $NavigationRail.Items | Where-Object { $_.IsSelected -eq "True" } | Select-Object -ExpandProperty name
}

function Get-SaveFilePath {
    # Opens a save-file windows dialog and returns the name and path of the file to be saved.
    Param (
        [string] $InitialDirectory,
        [string] $Filter
    )
    try {
        $SaveFileDialog = [Microsoft.Win32.SaveFileDialog]::New()
        $SaveFileDialog.initialDirectory = $InitialDirectory
        $SaveFileDialog.filter = $Filter
        $SaveFileDialog.CreatePrompt = $False;
        $SaveFileDialog.OverwritePrompt = $True;
        $SaveFileDialog.ShowDialog() | Out-Null
        return $SaveFileDialog.filename
    } catch {
        Write-Error "Error in Get-SaveFilePath common function`n$_"
    }
}

function Get-OpenFilePath {
    # Opens a open-file windows dialog and returns the name and path of the file to be opened.
    Param (
        [string] $InitialDirectory,
        [string] $Filter
    )
    try {
        $OpenFileDialog = [Microsoft.Win32.OpenFileDialog]::New()
        $OpenFileDialog.initialDirectory = $InitialDirectory
        $OpenFileDialog.filter = $Filter
        # Examples of other common filters: "Word Documents|*.doc|Excel Worksheets|*.xls|PowerPoint Presentations|*.ppt |Office Files|*.doc;*.xls;*.ppt |All Files|*.*"
        $OpenFileDialog.ShowDialog() | Out-Null
        return $OpenFileDialog.filename
    } catch {
        Write-Error "Error in Get-OpenFilePath common function`n$_"
    }
}

function Open-File {
    # Opens a file and gets its content based on the FileType parameter. default is Get-Content.
    param(
        $Path,
        $FileType
    )
    try {
        if (!(Test-Path $Path)) {
            Write-Error "File $Path not found"
            return
        }
        switch ($FileType) {
            "xml" {
                [xml]$OutputFile = (Get-Content -Path $Path)
            }
            "csv" {
                $OutputFile = (Import-Csv -Path $Path -Encoding UTF8)
            }
            default {
                $OutputFile = (Get-Content -Path $Path)
            }
        }
        return $OutputFile
    } catch {
        Write-Error "Error in Open-File common function`n$_"
    }
}

function Set-CurrentCulture {
    # Sets the PS Session's culture. All Time and Date UI controls will be effected by that. (DatePicker for example).
    param(
        $LCID = 2057
    )
    #  2057 = English (UK)   ,  1033 = English (US)
    $culture = [System.Globalization.CultureInfo]::GetCultureInfo($LCID)
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
}


function Set-OutlinedProperty {
    # Alters the visual style of some properties of a Material Design outlined UI control.
    param (
        [System.Management.Automation.PSObject[]]$InputObject,
        $Padding, # "2"
        $FloatingOffset, # "-15, 0"
        $FloatingScale, # "1.2"
        $Opacity, # "0.75"
        $FontSize
    )
    try {
        foreach ($UIObject in $InputObject) {
            if ($Padding) {
                $UIObject.padding = [System.Windows.Thickness]::new($Padding)
            }
            if ($FloatingOffset) {
                [MaterialDesignThemes.Wpf.HintAssist]::SetFloatingOffset( $UIObject, $FloatingOffset)
            }
            if ($FloatingScale) {
                [MaterialDesignThemes.Wpf.HintAssist]::SetFloatingScale( $UIObject, $FloatingScale)
            }
            if ($FontSize) {
                $UIObject.FontSize = $FontSize
            }
            if ($Opacity) {
                $UIObject.Opacity = $Opacity
            }
            $UIObject.VerticalContentAlignment = "Center"

        }
    } catch {
        Write-Error "Error in Set-OutlinedProperty common function`n$_"
    }
}

function Set-ValidationError {
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
    # Will call Set-ValidationError to Mark/Clear an element if its text is $null or not respectively.
    param (
        $UI_Object = $this,
        $ErrorText = "This field is mandatory"
    )
    if (!$UI_Object.Text) {
        Set-ValidationError -UIObject $UI_Object -ErrorText $ErrorText
    } else {
        Set-ValidationError -UIObject $UI_Object -ClearInvalid
    }
}

function Confirm-TextPatternField {
    # Will call Set-ValidationError to Mark/Clear an element if its text does not match or matches a regular expression respectively.
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
        Set-ValidationError -UIObject $UI_Object -ClearInvalid
    } else {
        Set-ValidationError -UIObject $UI_Object -ErrorText $ErrorText
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
function  Set-Theme {
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

function  Get-ThemeMode {
    # Returns the given app window theme mode ("Dark" or "Light")
    param(
        $Window
    )
    $Theme = [MaterialDesignThemes.Wpf.ResourceDictionaryExtensions]::GetTheme($Window.Resources)
    return [MaterialDesignThemes.Wpf.ThemeExtensions]::GetBaseTheme($Theme)
}

function Get-SystemTheme {
    # Will return "Dark" or "Light" based on the current apps theme mode set in windows OS
    return [MaterialDesignThemes.Wpf.Theme]::GetSystemTheme()
}
#endregion Theme

$Window = New-Window -XamlFile "$PSScriptRoot\AzureConfigUI.xaml"
$TextBox_Output.AppendText("Main Runspace ID: $(([System.Management.Automation.Runspaces.Runspace]::DefaultRunSpace).id)`n")
class ObjectOutPut {
    <# Define the class. Try constructors, properties, or methods. #>
}
$Btn_StartConfigJobs.Add_Click({
        $HsmConfigCard.IsEnabled = $false
        $SpinnerOverlayLayer.Visibility = "Visible"

        $Global:SyncHash = [hashtable]::Synchronized(@{
                Window              = $window
                SpinnerOverlayLayer = $SpinnerOverlayLayer
                TextBox_Output      = $TextBox_Output
                HsmConfigCard       = $HsmConfigCard
            }
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
$Btn_Popup_AZ_Inputs.Add_Click({
        $HsmConfigCard.IsEnabled = $true
        $Global:SyncHash = [hashtable]::Synchronized(@{
                Window              = $window
                SpinnerOverlayLayer = $SpinnerOverlayLayer
                TextBox_Output      = $TextBox_Output
                ActiveConfigCard    = $HsmConfigCard
            }
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $HsmConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)
$Btn_HsmConfigCard_Close.Add_Click({
        $HsmConfigCard.IsEnabled = $false
        $Global:SyncHash = [hashtable]::Synchronized(@{
                Window              = $window
                SpinnerOverlayLayer = $SpinnerOverlayLayer
                TextBox_Output      = $TextBox_Output
                ActiveConfigCard    = $HsmConfigCard
            }
        )
        $DarkBgOverlayLayer.Visibility = "Hidden"
        $HsmConfigCard.Visibility = "Hidden"
        $MainWindow.Height = 460
        $MainWindow.width = 450
    }
)

$Btn_Popup_AZ_user_Inputs.Add_Click({
        $azUserConfigCard.IsEnabled = $true
        $Global:SyncHash = [hashtable]::Synchronized(@{
                Window              = $window
                SpinnerOverlayLayer = $SpinnerOverlayLayer
                TextBox_Output      = $TextBox_Output
                ActiveConfigCard    = $azUserConfigCard
            }
        )
        $DarkBgOverlayLayer.Visibility = "Visible"
        $azUserConfigCard.Visibility = "Visible"
        $MainWindow.Height = 700
        $MainWindow.width = 550
    }
)

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