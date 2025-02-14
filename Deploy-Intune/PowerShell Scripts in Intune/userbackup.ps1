$DirectoryToCreate = $env:ProgramFiles+"\backup-restore"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}

##Download Backup Script
$backupurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/backup.bat"
$backupscript = $DirectoryToCreate+"\backup.bat"
Invoke-WebRequest -Uri $backupurl -OutFile $backupscript -UseBasicParsing

##Download Restore Script
$restoreurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/NEWrestore.bat"
$restorescript = $DirectoryToCreate+"\restore.bat"
Invoke-WebRequest -Uri $restoreurl -OutFile $restorescript -UseBasicParsing

##Download Silent Launch Script
$content = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.RUN "cmd /c c:\PROGRA~1\backup-restore\backup.bat", 0
"@

$launchscript = $DirectoryToCreate+"\run-invisible.vbs"
$content | Out-File $launchscript -UseBasicParsing



##Create scheduled task
# Create a new task action
$taskAction = New-ScheduledTaskAction -Execute 'C:\Program Files\backup-restore\run-invisible.vbs' 

##Create Trigger (login)
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn

# Register the new PowerShell scheduled task

#Name it
$taskName = "UserBackup"

#Describe it
$description = "Backs up User profile to OneDrive"

# Register it
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Description $description