# Delete and stop the service if it already exists.
if (Get-Service metricbeat -ErrorAction SilentlyContinue) {
  $service = Get-WmiObject -Class Win32_Service -Filter "name='metricbeat'"
  $service.StopService()
  Start-Sleep -s 1
  $service.delete()
}

$workdir = Split-Path $MyInvocation.MyCommand.Path

# Create the new service.
New-Service -name metricbeat `
  -displayName Metricbeat `
  -binaryPathName "`"$workdir\metricbeat.exe`" -c `"$workdir\metricbeat.yml`" -path.home `"$workdir`" -path.data `"C:\ProgramData\metricbeat`" -path.logs `"C:\ProgramData\metricbeat\logs`" -E logging.files.redirect_stderr=true"

# Attempt to set the service to delayed start using sc config.
Try {
  Start-Process -FilePath sc.exe -ArgumentList 'config metricbeat start= delayed-auto'
}
Catch { Write-Host -f red "An error occured setting the service to delayed start." }
