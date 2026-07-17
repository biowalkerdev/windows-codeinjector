$processName = Read-Host "Enter process name (Check in task manager)"
Get-Process | Where-Object { $_.ProcessName -like "*$processName*" } | Select-Object ProcessName, Id