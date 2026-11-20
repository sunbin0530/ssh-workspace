param(
    [string]$PythonExe = 'python',
    [switch]$RegisterCodex
)
$ErrorActionPreference = 'Stop'
$venv = Join-Path $PSScriptRoot '.venv'
$localPython = Join-Path $venv 'Scripts\python.exe'
$server = Join-Path $PSScriptRoot 'mcp_server.py'

if (-not (Test-Path -LiteralPath $localPython)) {
    & $PythonExe -c 'import sys, tkinter; assert sys.version_info >= (3, 11), "Python 3.11 or later is required"'
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.11 or later with Tcl/Tk, or pass -PythonExe.' }
    & $PythonExe -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the local Python environment.' }
}

& $localPython -m pip install --require-hashes -r (Join-Path $PSScriptRoot 'requirements.lock')
if ($LASTEXITCODE -ne 0) { throw 'Could not install Python dependencies.' }
& $localPython -c 'import tkinter, paramiko, mcp, starlette, uvicorn, websockets'
if ($LASTEXITCODE -ne 0) { throw 'Installed Python cannot load SSH Workspace dependencies.' }

if ($RegisterCodex) {
    & $localPython (Join-Path $PSScriptRoot 'register_mcp.py')
    if ($LASTEXITCODE -ne 0) { throw 'Could not register SSH Workspace with Codex.' }
}

Write-Output "MCP command: $localPython"
Write-Output "MCP argument: $server"
