$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcut = $ws.CreateShortcut("$desktop\Hack Tracker.lnk")
$shortcut.TargetPath = "$PSScriptRoot\node_modules\electron\dist\electron.exe"
$shortcut.Arguments = "."
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.IconLocation = "$PSScriptRoot\node_modules\electron\dist\electron.exe"
$shortcut.Save()
Write-Output "Shortcut created at $desktop\Hack Tracker.lnk"
