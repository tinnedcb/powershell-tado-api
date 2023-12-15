# Tado API Data Exporter for PowerShell
Making it simple to export all measurement data from your Tado heating system using a Windows machine, or via PowerShell 7+ running on Linux.

## Getting started
1. Download the repo to a local directory and run the `PsConsole.bat` file from a Windows machine to open a PowerShell console with all the required functions loaded.
2. Set where you want the data from Tado exported to, using the command `Set-TadoDataDirectory -DataDirectory 'C:\Users\MyUser\Documents\Tado-Data'` changing the `DataDirectory` to your chosen location.
This directory will be stored for use next time in the root of your users profile directory, in the file `.TadoApiConfig.json`.
3. Set your Tado credentials with the command `Set-TadoDefaulCredentials`. You will be prompted to securely enter your Tado user credentials. Your password will be encrypted and stored in the file `TadoApiCreds.json` for use whenever you call the Tado methods in this library.

To now export all available Tado data run the `Export-TadoData` command.
