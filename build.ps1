$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    dotnet publish src/ColdWarDemo.App/ColdWarDemo.App.csproj -c Release -r win-x64 --self-contained true -o publish
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    Write-Host 'Ready: publish/ColdWarDemoTool.exe'
}
finally { Pop-Location }
