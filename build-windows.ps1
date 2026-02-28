$ErrorActionPreference = "Stop"

go mod tidy

# Build GUI exe (no console window)
go build -ldflags "-H=windowsgui" -o spycam-desktop.exe .

mkdir -Force dist\windows | Out-Null
copy spycam-desktop.exe dist\windows\
copy README.txt dist\windows\

Compress-Archive -Path dist\windows\* -DestinationPath spycam-desktop-windows.zip -Force
Write-Host "Built spycam-desktop-windows.zip"